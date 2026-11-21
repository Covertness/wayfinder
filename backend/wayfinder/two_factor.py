from base64 import b32encode

from django import forms
from django.contrib.admin.forms import AdminAuthenticationForm
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django_otp.plugins.otp_totp.models import TOTPDevice
from dj_rest_auth.serializers import LoginSerializer
from drf_spectacular.utils import extend_schema, inline_serializer
from rest_framework import serializers, status
from rest_framework.authentication import SessionAuthentication
from rest_framework.response import Response
from rest_framework.views import APIView


def verify_device_token(device, token):
    if (
        not isinstance(token, str)
        or len(token) != 6
        or not token.isascii()
        or not token.isdigit()
    ):
        token = "invalid"
    return device.verify_token(token)


def verify_user_token(user, token):
    """Verify while holding a row lock so codes cannot be reused concurrently."""
    with transaction.atomic():
        get_user_model().objects.select_for_update().get(pk=user.pk)
        device = TOTPDevice.objects.select_for_update().filter(
            user=user, confirmed=True
        ).first()
        if device is None:
            return "not_enabled"
        if not token:
            return "required"
        return "valid" if verify_device_token(device, token) else "invalid"


class TwoFactorLoginSerializer(LoginSerializer):
    otp = serializers.CharField(required=False, allow_blank=True, write_only=True)

    def validate(self, attrs):
        attrs = super().validate(attrs)
        result = verify_user_token(attrs["user"], attrs.get("otp"))
        if result == "required":
            raise serializers.ValidationError(
                {"otp": ["Two-factor code required."]}, code="otp_required"
            )
        if result == "invalid":
            raise serializers.ValidationError(
                {"otp": ["Invalid or temporarily throttled two-factor code."]}
            )
        return attrs


class TwoFactorAdminAuthenticationForm(AdminAuthenticationForm):
    otp_token = forms.CharField(
        label="Authenticator code", required=False,
        widget=forms.TextInput(attrs={"autocomplete": "one-time-code", "inputmode": "numeric"}),
    )

    def clean(self):
        cleaned_data = super().clean()
        result = verify_user_token(self.get_user(), cleaned_data.get("otp_token"))
        if result in ("required", "invalid"):
            raise forms.ValidationError("Enter a valid authenticator code. Try again later if temporarily throttled.")
        return cleaned_data


class TwoFactorActionSerializer(serializers.Serializer):
    action = serializers.ChoiceField(choices=("setup", "confirm", "disable"))
    password = serializers.CharField(required=False, allow_blank=True, write_only=True, trim_whitespace=False)
    otp = serializers.CharField(required=False, allow_blank=True, write_only=True)


@method_decorator(never_cache, name="dispatch")
class TwoFactorView(APIView):
    authentication_classes = [SessionAuthentication]

    @extend_schema(responses=inline_serializer(
        name="TwoFactorStatus", fields={"enabled": serializers.BooleanField()}
    ))
    def get(self, request):
        return Response({"enabled": TOTPDevice.objects.filter(user=request.user, confirmed=True).exists()})

    @extend_schema(
        request=TwoFactorActionSerializer,
        responses={200: inline_serializer(
            name="TwoFactorResult",
            fields={
                "enabled": serializers.BooleanField(required=False),
                "secret": serializers.CharField(required=False),
                "uri": serializers.CharField(required=False),
            },
        )},
    )
    def post(self, request):
        serializer = TwoFactorActionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        action = data["action"]
        if action in ("setup", "disable") and not request.user.check_password(data.get("password", "")):
            return Response({"detail": "Incorrect password."}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            get_user_model().objects.select_for_update().get(pk=request.user.pk)
            devices = TOTPDevice.objects.select_for_update().filter(user=request.user)
            enabled = devices.filter(confirmed=True).first()

            if action == "setup":
                if enabled:
                    return Response({"detail": "Two-factor authentication is already enabled."}, status=400)
                devices.filter(confirmed=False).delete()
                device = TOTPDevice.objects.create(user=request.user, name="Authenticator", confirmed=False)
                return Response({"secret": b32encode(device.bin_key).decode(), "uri": device.config_url})

            device = enabled if action == "disable" else devices.filter(confirmed=False).first()
            if device is None or (action == "confirm" and enabled):
                return Response({"detail": "No matching two-factor setup found."}, status=400)
            if not verify_device_token(device, data.get("otp", "")):
                return Response({"detail": "Invalid or temporarily throttled authenticator code."}, status=400)
            if action == "confirm":
                device.confirmed = True
                device.save(update_fields=["confirmed"])
            else:
                devices.delete()
        return Response({"enabled": action == "confirm"})
