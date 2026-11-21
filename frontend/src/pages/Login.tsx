import { LoginForm } from "@/components/login/LoginForm";
import type { LoginFormValues } from "@/components/login/LoginForm";
import { toast } from "sonner";
import RedirectIfAuthenticatedLayout from "@/layouts/RedirectIfAuthenticatedLayout";
import { authLoginCreate } from "@/api/django/auth/auth";
import axios from "axios";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import Icon from "@/assets/icon.svg?react";

const Login = () => {
  const navigate = useNavigate();
  const [isLoading, setIsLoading] = useState(false);
  const [otpRequired, setOtpRequired] = useState(false);

  const handleLogin = async (formData: LoginFormValues) => {
    try {
      setIsLoading(true);
      await authLoginCreate(formData);
      navigate("/");
    } catch (error: unknown) {
      console.error("Error logging in", error);
      if (axios.isAxiosError(error) && Array.isArray(error.response?.data?.otp)) {
        setOtpRequired(true);
        if (formData.otp) {
          toast.error("Invalid or temporarily throttled authenticator code.");
        }
      } else {
        toast.error("Unable to log in. Check your credentials and try again.");
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <RedirectIfAuthenticatedLayout>
      <div className="bg-background flex min-h-svh flex-col items-center justify-center gap-6 p-6 md:p-10">
        <div className="w-full max-w-sm">
          <div className={"flex flex-col gap-6"}>
            {/* Header */}
            <div className="flex flex-col items-center gap-2">
              <a
                href="#"
                className="flex flex-col items-center gap-2 font-medium"
              >
                <span className="sr-only">Wayfinder</span>
              </a>
              <Icon className="h-[50px]" />
              <h1 className="text-xl font-bold">Welcome to Wayfinder</h1>
            </div>
            <LoginForm onSubmit={handleLogin} isSubmitting={isLoading} otpRequired={otpRequired} />
          </div>
        </div>
      </div>
    </RedirectIfAuthenticatedLayout>
  );
};

export default Login;
