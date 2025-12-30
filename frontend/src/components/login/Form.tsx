// Reacts
import { useState } from "react";
import { Link } from "react-router-dom";

// Icons
import { Eye, EyeOff, Loader2, AlertCircle } from "lucide-react";

// Types
import type { LoginFormProps } from "../../types/forms";

const LoginForm = ({ formData, isLoading, feedback, onSubmit, onChange }: LoginFormProps) => {
  // Hooks
  const [showPassword, setShowPassword] = useState<boolean>(false);

  return (
    <>
      <form onSubmit={onSubmit} noValidate>
        {/* Email */}
        <div className="form-floating mb-3">
          <input
            type="email"
            className="form-control"
            id="email"
            name="email"
            value={formData.email}
            onChange={onChange}
            placeholder="name@example.com"
            disabled={isLoading}
          />
          <label htmlFor="email">Email</label>
        </div>

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
              name="password"
              value={formData.password}
              onChange={onChange}
              placeholder="Enter password"
              disabled={isLoading}
              style={{ borderLeft: "none" }}
            />
            <label htmlFor="password">Password</label>
          </div>
        </div>

        {/* Forgot Password */}
        <div className="text-end mb-3">
          <Link
            to="/forgot-password"
            className="text-decoration-none small"
            style={{ color: "#7c3aed" }}
          >
            Forgot Password?
          </Link>
        </div>

        {/* Error Message */}
        {feedback.message && feedback.type === "error" && (
          <div className="alert alert-danger d-flex align-items-center mb-4" role="alert">
            <AlertCircle size={20} className="me-2 flex-shrink-0" />
            <div>{feedback.message}</div>
          </div>
        )}

        {/* Submit Button */}
        <div className="d-grid">
          <button
            type="submit"
            className="btn fw-semibold text-white d-flex align-items-center justify-content-center gap-2"
            style={{
              background: "linear-gradient(135deg, #0051e6 0%, #7c3aed 100%)",
              border: "none",
              opacity: isLoading ? 0.8 : 1,
              height: "48px",
            }}
            disabled={isLoading}
          >
            {isLoading ? (
              <>
                <Loader2
                  size={20}
                  className="animate-spin"
                  style={{ animation: "spin 1s linear infinite" }}
                />
                Signing In...
              </>
            ) : (
              "Sign In"
            )}
          </button>
        </div>
      </form>

      {/* Spinner animation */}
      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </>
  );
};

export default LoginForm;
