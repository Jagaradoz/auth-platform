// Reacts
import { useEffect, useState, useRef } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

// Icons
import { CheckCircle, XCircle, Loader } from "lucide-react";

// Hooks
import useAuth from "../hooks/useAuth";

const Verify = () => {
  // Hooks
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { verifyEmail } = useAuth();
  const [status, setStatus] = useState<"loading" | "success" | "error">("loading");
  const [message, setMessage] = useState("");
  const hasVerified = useRef(false);

  // Effects
  useEffect(() => {
    const token = searchParams.get("token");

    if (!token) {
      setStatus("error");
      setMessage("Verification token is missing.");
      return;
    }

    if (hasVerified.current) return;
    hasVerified.current = true;

    const verify = async () => {
      try {
        await verifyEmail(token);
        setStatus("success");
        setMessage("Your email has been verified successfully!");
      } catch (error: unknown) {
        setStatus("error");
        const apiError = error as { response?: { data?: { message?: string } }; message?: string };
        setMessage(
          apiError.response?.data?.message ||
            apiError.message ||
            "Verification failed. The link may be invalid or expired.",
        );
      }
    };

    verify();
  }, [searchParams, verifyEmail]);

  // Functions
  const handleContinue = () => {
    navigate("/login");
  };

  return (
    <div className="container-fluid min-vh-100 d-flex align-items-center justify-content-center bg-section">
      <div
        className="card border-0 position-relative text-center"
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
              width: "80px",
              height: "80px",
              borderRadius: "50%",
              background:
                status === "loading"
                  ? "linear-gradient(135deg, #6c757d 0%, #495057 100%)"
                  : status === "success"
                    ? "linear-gradient(135deg, #28a745 0%, #20c997 100%)"
                    : "linear-gradient(135deg, #dc3545 0%, #c82333 100%)",
            }}
          >
            {status === "loading" && <Loader size={40} color="white" className="animate-spin" />}
            {status === "success" && <CheckCircle size={40} color="white" />}
            {status === "error" && <XCircle size={40} color="white" />}
          </div>

          {/* Title */}
          <h2 className="fw-bold mb-3" style={{ color: "#1a1a2e" }}>
            {status === "loading" && "Verifying..."}
            {status === "success" && "Email Verified!"}
            {status === "error" && "Verification Failed"}
          </h2>

          {/* Description */}
          <p className="text-muted mb-4">
            {message || "Please wait while we verify your email..."}
          </p>

          {/* Continue Button - only show when not loading */}
          {status !== "loading" && (
            <button
              onClick={handleContinue}
              className="btn w-100 d-flex align-items-center justify-content-center gap-2"
              style={{
                background:
                  status === "success"
                    ? "linear-gradient(135deg, #28a745 0%, #20c997 100%)"
                    : "linear-gradient(135deg, #7c3aed 0%, #0051e6 100%)",
                color: "white",
                padding: "12px",
                fontWeight: 600,
                border: "none",
              }}
            >
              {status === "success" ? "Continue to Login" : "Back to Login"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default Verify;
