import type { RegisterFormData, LoginFormData, ValidationErrors, ValidationResult } from "../types";

const strengthLabels: string[] = ["Very Weak", "Weak", "Fair", "Good", "Strong"];
const strengthColors: string[] = ["#ef4444", "#f97316", "#eab308", "#22c55e", "#10b981"];

type FormData = RegisterFormData | LoginFormData;

/** Checks if formData contains a password field (type guard). */
const hasPassword = (formData: FormData): formData is FormData => {
  return "password" in formData;
};

/** Validates a single form field based on field name and value. */
const validateField = (name: string, value: string, formData?: FormData): string => {
  switch (name) {
    case "email":
      if (!value) return "Email is required";
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return "Please enter a valid email address";
      return "";
    case "password":
      if (!value) return "Password is required";
      if (value.length < 6) return "Password must be at least 6 characters";
      return "";
    case "confirmPassword":
      if (!value) return "Please confirm your password";
      if (formData && hasPassword(formData) && value !== formData.password)
        return "Passwords do not match";
      return "";
    default:
      return "";
  }
};

/** Validates all form fields at once for submission. */
const validateForm = (formData: FormData): ValidationResult => {
  const errors: ValidationErrors = {};
  (Object.keys(formData) as Array<keyof typeof formData>).forEach((field) => {
    const error = validateField(field, formData[field], formData);
    if (error) errors[field] = error;
  });
  return {
    errors,
    isValid: Object.keys(errors).length === 0,
  };
};

/** Calculates password strength score (0-5) based on complexity criteria. */
const getPasswordStrength = (password: string): number => {
  let strength = 0;
  if (password.length >= 8) strength++;
  if (/[a-z]/.test(password)) strength++;
  if (/[A-Z]/.test(password)) strength++;
  if (/[0-9]/.test(password)) strength++;
  if (/[^a-zA-Z0-9]/.test(password)) strength++;
  return strength;
};

// Exports
export { strengthLabels, strengthColors, validateField, validateForm, getPasswordStrength };
