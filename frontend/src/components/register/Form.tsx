// Reacts
import { useState } from "react";

// Icons
import { Eye, EyeOff, Loader2, CheckCircle, AlertCircle, Check, X } from "lucide-react";

// Types
import type { RegisterFormData } from "../../types/forms";
import type { RegisterFormProps } from "../../types/forms";

const RegisterForm = ({
  formData,
  errors,
  isLoading,
  feedback,
  onSubmit,
  onChange,
}: RegisterFormProps) => {
  // Hooks
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState<boolean>(false);

  // Functions
  const getValidationClass = (fieldName: keyof RegisterFormData): string => {
    if (!formData[fieldName]) return ""; // No validation styling for empty fields
    return errors[fieldName] ? "is-invalid" : "is-valid";
  };

  const showValidIcon = (fieldName: keyof RegisterFormData): boolean =>
    Boolean(formData[fieldName] && !errors[fieldName]);
  const showInvalidIcon = (fieldName: keyof RegisterFormData): boolean =>
    Boolean(formData[fieldName] && errors[fieldName]);

  return (
    <>
      <form onSubmit={onSubmit} noValidate>
        {/* Email */}
        <div className="form-floating mb-1 position-relative">
          <input
            type="email"
            className={`form-control ${getValidationClass("email")}`}
            id="email"
            name="email"
            value={formData.email}
            onChange={onChange}
            placeholder="name@example.com"
            disabled={isLoading}
          />
          <label htmlFor="email">Email</label>
          {showValidIcon("email") && (
            <Check
              size={18}
              className="text-success position-absolute"
              style={{ right: "12px", top: "50%", transform: "translateY(-50%)" }}
            />
          )}
          {showInvalidIcon("email") && (
            <X
              size={18}
              className="text-danger position-absolute"
              style={{ right: "12px", top: "50%", transform: "translateY(-50%)" }}
            />
          )}
        </div>
        <div style={{ minHeight: "24px" }} className="mb-2">
          {errors.email && <small className="text-danger">{errors.email}</small>}
        </div>

        {/* Password */}
        <div className="input-group mb-1">
          <button
            type="button"
            className="btn btn-outline-secondary d-flex align-items-center"
            onClick={() => setShowPassword(!showPassword)}
            tabIndex={-1}
            style={{ borderColor: "#dee2e6" }}
          >
            {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
          </button>
          <div className="form-floating flex-grow-1 position-relative">
            <input
              type={showPassword ? "text" : "password"}
              className={`form-control ${getValidationClass("password")}`}
              id="password"
              name="password"
              value={formData.password}
              onChange={onChange}
              placeholder="Enter password"
              disabled={isLoading}
              style={{ borderLeft: "none" }}
            />
            <label htmlFor="password">Password</label>
            {showValidIcon("password") && (
              <Check
                size={18}
                className="text-success position-absolute"
                style={{ right: "12px", top: "50%", transform: "translateY(-50%)" }}
              />
            )}
            {showInvalidIcon("password") && (
              <X
                size={18}
                className="text-danger position-absolute"
                style={{ right: "12px", top: "50%", transform: "translateY(-50%)" }}
              />
            )}
          </div>
        </div>
        <div style={{ minHeight: "24px" }} className="mb-2">
          {errors.password && <small className="text-danger">{errors.password}</small>}
        </div>

        {/* Confirm Password */}
        <div className="input-group mb-1">
          <button
            type="button"
            className="btn btn-outline-secondary d-flex align-items-center"
            onClick={() => setShowConfirmPassword(!showConfirmPassword)}
            tabIndex={-1}
            style={{ borderColor: "#dee2e6" }}
          >
            {showConfirmPassword ? <EyeOff size={18} /> : <Eye size={18} />}
          </button>
          <div className="form-floating flex-grow-1 position-relative">
            <input
              type={showConfirmPassword ? "text" : "password"}
              className={`form-control ${getValidationClass("confirmPassword")}`}
              id="confirmPassword"
              name="confirmPassword"
              value={formData.confirmPassword}
              onChange={onChange}
              placeholder="Confirm password"
              disabled={isLoading}
              style={{ borderLeft: "none" }}
            />
            <label htmlFor="confirmPassword">Confirm Password</label>
            {showValidIcon("confirmPassword") && (
              <Check
                size={18}
                className="text-success position-absolute"
                style={{ right: "12px", top: "50%", transform: "translateY(-50%)" }}
              />
            )}
            {showInvalidIcon("confirmPassword") && (
              <X
                size={18}
                className="text-danger position-absolute"
                style={{ right: "12px", top: "50%", transform: "translateY(-50%)" }}
              />
            )}
          </div>
        </div>
        <div style={{ minHeight: "24px" }} className="mb-2">
          {errors.confirmPassword && (
            <small className="text-danger">{errors.confirmPassword}</small>
          )}
        </div>

        {/* Feedback Message (Success/Error) */}
        {feedback.message && (
          <div
            className={`alert ${feedback.type === "success" ? "alert-success" : "alert-danger"} d-flex align-items-center mb-4`}
            role="alert"
          >
            {feedback.type === "success" ? (
              <CheckCircle size={20} className="me-2 flex-shrink-0" />
            ) : (
              <AlertCircle size={20} className="me-2 flex-shrink-0" />
            )}
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
                Creating Account...
              </>
            ) : (
              "Create Account"
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
        .form-control.is-valid,
        .form-control.is-invalid {
          background-image: none !important;
          padding-right: 0.75rem !important;
        }
      `}</style>
    </>
  );
};

export default RegisterForm;
