// Reacts
import { Link } from "react-router-dom";

// Icons
import { Mail, ArrowLeft } from "lucide-react";

const CheckEmail = () => {
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
              background: "linear-gradient(135deg, #7c3aed 0%, #0051e6 100%)",
            }}
          >
            <Mail size={40} color="white" />
          </div>

          {/* Title */}
          <h2 className="fw-bold mb-3" style={{ color: "#1a1a2e" }}>
            Check Your Email
          </h2>

          {/* Description */}
          <p className="text-muted mb-4">
            We've sent a verification link to your email address. Please check your inbox and click
            the link to verify your account.
          </p>

          {/* Back to Login */}
          <Link
            to="/login"
            className="btn w-100 d-flex align-items-center justify-content-center gap-2"
            style={{
              background: "linear-gradient(135deg, #7c3aed 0%, #0051e6 100%)",
              color: "white",
              padding: "12px",
              fontWeight: 600,
              border: "none",
            }}
          >
            <ArrowLeft size={18} />
            Back to Login
          </Link>
        </div>
      </div>
    </div>
  );
};

export default CheckEmail;
