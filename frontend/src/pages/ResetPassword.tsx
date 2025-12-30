// Reacts
import { useState, useEffect, useRef } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

// Icons
import { Lock, Loader2, CheckCircle, AlertCircle, Eye, EyeOff } from "lucide-react";

// Hooks
import useAuth from "../hooks/useAuth";

const ResetPassword = () => {
  // Hooks
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { resetPassword } = useAuth();
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [status, setStatus] = useState<"idle" | "success" | "error">("idle");
  const [message, setMessage] = useState("");
  const hasCheckedToken = useRef(false);

  // Effects
  useEffect(() => {
    if (hasCheckedToken.current) return;
    hasCheckedToken.current = true;

    const token = searchParams.get("token");
    if (!token) {
      setStatus("error");
      setMessage("Invalid or missing reset token.");
    }
  }, [searchParams]);

  // Functions
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const token = searchParams.get("token");
    if (!token) {
      setStatus("error");
      setMessage("Invalid or missing reset token.");
      return;
    }

    if (!password || !confirmPassword) {
      setStatus("error");
      setMessage("Please fill in all fields.");
      return;
    }

    if (password.length < 6) {
      setStatus("error");
      setMessage("Password must be at least 6 characters.");
      return;
    }

    if (password !== confirmPassword) {
      setStatus("error");
      setMessage("Passwords do not match.");
      return;
    }

    setIsLoading(true);
    try {
      await resetPassword(token, password);
      setStatus("success");
      setMessage("Password reset successfully! You can now log in.");
    } catch (error: unknown) {
      setStatus("error");
      const apiError = error as { response?: { data?: { message?: string } } };
      setMessage(
        apiError.response?.data?.message || "Failed to reset password. The link may be expired.",
      );
    } finally {
      setIsLoading(false);
    }
  };

  const handleContinue = () => {
    navigate("/login");
  };

  return (
    <div className="container-fluid min-vh-100 d-flex align-items-center justify-content-center bg-section">
      <div
        className="card border-0 position-relative"
        style={{
          maxWidth: "450px",
          width: "100%",
          background: "rgba(255, 255, 255, 0.95)",
          backdropFilter: "blur(10px)",
          boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.4)",
        }}
      >
        <div className="card-body p-5">
          {/* Icon */}
          <div
            className="d-flex align-items-center justify-content-center mx-auto mb-4"
            style={{
              width: "70px",
              height: "70px",
              borderRadius: "50%",
              background:
                status === "success"
                  ? "linear-gradient(135deg, #28a745 0%, #20c997 100%)"
                  : "linear-gradient(135deg, #7c3aed 0%, #0051e6 100%)",
            }}
          >
            {status === "success" ? (
              <CheckCircle size={32} color="white" />
            ) : (
              <Lock size={32} color="white" />
            )}
          </div>

          {/* Title */}
          <h2 className="fw-bold text-center mb-2" style={{ color: "#1a1a2e" }}>
            {status === "success" ? "Password Reset!" : "Reset Password"}
          </h2>
          <p className="text-muted text-center mb-4">
            {status === "success"
              ? "Your password has been changed successfully."
              : "Enter your new password below."}
          </p>

          {/* Error Message */}
          {status === "error" && (
            <div className="alert alert-danger d-flex align-items-center gap-2 py-2">
              <AlertCircle size={18} />
              {message}
            </div>
          )}

          {/* Form */}
          {status !== "success" && (
            <form onSubmit={handleSubmit}>
              {/* Password */}
              <div className="input-group mb-3">
                <button
                  type="button"
                  className="btn btn-outline-secondary d-flex align-items-center"
                  onClick={() => setShowPassword(!showPassword)}
                  tabIndex={-1}
                  style={{ borderColor: "#dee2e6" }}
                >
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
                <div className="form-floating flex-grow-1">
                  <input
                    type={showPassword ? "text" : "password"}
                    className="form-control"
                    id="password"
                    placeholder="Enter new password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    disabled={isLoading}
                    style={{ borderLeft: "none" }}
                  />
                  <label htmlFor="password">New Password</label>
                </div>
              </div>

              {/* Confirm Password */}
              <div className="input-group mb-4">
                <button
                  type="button"
                  className="btn btn-outline-secondary d-flex align-items-center"
                  onClick={() => setShowPassword(!showPassword)}
                  tabIndex={-1}
                  style={{ borderColor: "#dee2e6" }}
                >
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
                <div className="form-floating flex-grow-1">
                  <input
                    type={showPassword ? "text" : "password"}
                    className="form-control"
                    id="confirmPassword"
                    placeholder="Confirm new password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    disabled={isLoading}
                    style={{ borderLeft: "none" }}
                  />
                  <label htmlFor="confirmPassword">Confirm Password</label>
                </div>
              </div>

              <button
                type="submit"
                className="btn w-100 d-flex align-items-center justify-content-center gap-2"
                style={{
                  background: "linear-gradient(135deg, #7c3aed 0%, #0051e6 100%)",
                  color: "white",
                  padding: "12px",
                  fontWeight: 600,
                  border: "none",
                }}
                disabled={isLoading}
              >
                {isLoading ? (
                  <>
                    <Loader2 size={18} style={{ animation: "spin 1s linear infinite" }} />
                    Resetting...
                  </>
                ) : (
                  "Reset Password"
                )}
              </button>
            </form>
          )}

          {/* Success - Continue to Login */}
          {status === "success" && (
            <button
              onClick={handleContinue}
              className="btn w-100 d-flex align-items-center justify-content-center gap-2"
              style={{
                background: "linear-gradient(135deg, #28a745 0%, #20c997 100%)",
                color: "white",
                padding: "12px",
                fontWeight: 600,
                border: "none",
              }}
            >
              Continue to Login
            </button>
          )}
        </div>
      </div>

      {/* Spinner animation */}
      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
};

export default ResetPassword;
