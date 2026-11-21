from django_otp.plugins.otp_totp.models import TOTPDevice
from drf_spectacular.extensions import OpenApiAuthenticationExtension
from drf_spectacular.plumbing import build_bearer_security_scheme_object
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed


class SessionOrIntegrationTokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, key):
        user, token = super().authenticate_credentials(key)
        if TOTPDevice.objects.filter(user=user, confirmed=True).exists():
            raise AuthenticationFailed("Use a two-factor authenticated session.")
        return user, token


class SessionOrIntegrationTokenScheme(OpenApiAuthenticationExtension):
    target_class = "wayfinder.authentication.SessionOrIntegrationTokenAuthentication"
    name = "apiTokenAuth"

    def get_security_definition(self, auto_schema):
        return build_bearer_security_scheme_object(
            header_name="Authorization", token_prefix=self.target.keyword
        )
