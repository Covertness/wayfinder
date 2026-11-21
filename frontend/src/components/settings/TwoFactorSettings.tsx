import { useEffect, useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import { toast } from "sonner";
import axios from "axios";
import { customAxiosInstance } from "@/api/axios";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

type Setup = { secret: string; uri: string };
const url = "/wayfinder/settings/two-factor/";

function errorMessage(error: unknown): string {
  if (axios.isAxiosError(error) && typeof error.response?.data?.detail === "string") {
    return error.response.data.detail;
  }
  return "Could not update two-factor authentication. Please try again.";
}

export default function TwoFactorSettings() {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [setup, setSetup] = useState<Setup | null>(null);
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [busy, setBusy] = useState(false);
  const [loadError, setLoadError] = useState(false);
  const [loadAttempt, setLoadAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    customAxiosInstance<{ enabled: boolean }>({ url, method: "GET", signal: controller.signal })
      .then((result) => setEnabled(result.enabled))
      .catch((error: unknown) => {
        if (!axios.isCancel(error)) {
          console.error("Failed to load two-factor status", error);
          setLoadError(true);
          toast.error("Could not load two-factor authentication status.");
        }
      });
    return () => controller.abort();
  }, [loadAttempt]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      if (!enabled && !setup) {
        const result = await customAxiosInstance<Setup>({
          url, method: "POST", data: { action: "setup", password }
        });
        setPassword("");
        setSetup(result);
      } else {
        const result = await customAxiosInstance<{ enabled: boolean }>({
          url, method: "POST",
          data: { action: enabled ? "disable" : "confirm", password, otp }
        });
        setEnabled(result.enabled);
        setSetup(null);
        setPassword("");
        setOtp("");
        toast.success(result.enabled ? "Two-factor authentication enabled." : "Two-factor authentication disabled.");
      }
    } catch (error: unknown) {
      console.error("Failed to update two-factor authentication", error);
      toast.error(errorMessage(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card className="max-w-lg">
      <CardHeader>
        <CardTitle>Two-factor authentication</CardTitle>
        <CardDescription>
          {enabled === null ? (loadError ? "Could not load status." : "Loading status...") : enabled
            ? "An authenticator code is required when you sign in."
            : "Protect your account with an authenticator app."}
        </CardDescription>
      </CardHeader>
      {enabled === null && loadError && (
        <CardContent>
          <Button type="button" variant="outline" onClick={() => { setLoadError(false); setLoadAttempt((attempt) => attempt + 1); }}>
            Retry
          </Button>
        </CardContent>
      )}
      {enabled !== null && (
        <CardContent>
          <form onSubmit={submit} className="space-y-4">
            {setup && (
              <div className="space-y-3">
                <p>Scan this code with your authenticator app, or enter the setup key manually.</p>
                <div className="w-fit rounded bg-white p-3"><QRCodeSVG value={setup.uri} size={180} /></div>
                <p className="break-all font-mono text-sm">{setup.secret}</p>
                <p className="text-sm text-muted-foreground">If you lose your authenticator, an administrator must reset two-factor authentication.</p>
              </div>
            )}
            {(!setup || enabled) && (
              <div className="space-y-2">
                <Label htmlFor="two-factor-password">Current password</Label>
                <Input id="two-factor-password" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
              </div>
            )}
            {(setup || enabled) && (
              <div className="space-y-2">
                <Label htmlFor="two-factor-otp">Authenticator code</Label>
                <Input id="two-factor-otp" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required value={otp} onChange={(e) => setOtp(e.target.value)} />
              </div>
            )}
            <div className="flex gap-2">
              <Button type="submit" loading={busy}>{enabled ? "Disable" : setup ? "Verify and enable" : "Set up"}</Button>
              {setup && <Button type="button" variant="outline" onClick={() => { setSetup(null); setOtp(""); }}>Cancel</Button>}
            </div>
          </form>
        </CardContent>
      )}
    </Card>
  );
}
