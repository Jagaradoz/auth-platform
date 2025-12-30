// Reacts
import { useState } from "react";
import { Link } from "react-router-dom";

// Icons
import { Mail, ArrowLeft, Loader2, CheckCircle, AlertCircle } from "lucide-react";

// Hooks
import useAuth from "../hooks/useAuth";

const ForgotPassword = () => {
  // Hooks
  const { forgotPassword } = useAuth();
  const [email, setEmail] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [status, setStatus] = useState<"idle" | "success" | "error">("idle");
  const [message, setMessage] = useState("");

  // Functions
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!email) {
      setStatus("error");
      setMessage("Please enter your email address");
      return;
    }

    setIsLoading(true);
    try {
      await forgotPassword(email);
      setStatus("success");
      setMessage("If an account with that email exists, a password reset link has been sent.");
    } catch {
      setStatus("error");
      setMessage("Something went wrong. Please try again.");
    } finally {
      setIsLoading(false);
    }
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
              background: "linear-gradient(135deg, #7c3aed 0%, #0051e6 100%)",
            }}
          >
            <Mail size={32} color="white" />
          </div>

          {/* Title */}
          <h2 className="fw-bold text-center mb-2" style={{ color: "#1a1a2e" }}>
            Forgot Password
          </h2>
          <p className="text-muted text-center mb-4">
            Enter your email and we'll send you a reset link.
          </p>

          {/* Status Messages */}
          {status === "success" && (
            <div className="alert alert-success d-flex align-items-center gap-2 py-2">
              <CheckCircle size={18} />
              {message}
            </div>
          )}
          {status === "error" && (
            <div className="alert alert-danger d-flex align-items-center gap-2 py-2">
              <AlertCircle size={18} />
              {message}
            </div>
          )}

          {/* Form */}
          {status !== "success" && (
            <form onSubmit={handleSubmit}>
              <div className="form-floating mb-4">
                <input
                  type="email"
                  className="form-control"
                  id="email"
                  placeholder="name@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  disabled={isLoading}
                />
                <label htmlFor="email">Email</label>
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
                    Sending...
                  </>
                ) : (
                  "Send Reset Link"
                )}
              </button>
            </form>
          )}

          {/* Back to Login */}
          <div className="text-center mt-4">
            <Link
              to="/login"
              className="text-decoration-none d-inline-flex align-items-center gap-1"
              style={{ color: "#7c3aed" }}
            >
              <ArrowLeft size={16} />
              Back to Login
            </Link>
          </div>
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

export default ForgotPassword;
