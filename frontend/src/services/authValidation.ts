// Packages
import { z } from "zod";

// Types
import type { RegisterFormData } from "../types/forms";
import type { ValidationErrors, ValidationResult } from "../types/validation";

// Zod Schemas
const emailSchema = z
  .string()
  .min(1, "Email is required")
  .email("Please enter a valid email address");

const passwordSchema = z
  .string()
  .min(1, "Password is required")
  .min(6, "Password must be at least 6 characters");

const registerSchema = z
  .object({
    email: emailSchema,
    password: passwordSchema,
    confirmPassword: z.string().min(1, "Please confirm your password"),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "Passwords do not match",
    path: ["confirmPassword"],
  });

const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, "Password is required"),
});

// Constants
const strengthLabels: string[] = ["Very Weak", "Weak", "Fair", "Good", "Strong"];
const strengthColors: string[] = ["#ef4444", "#f97316", "#eab308", "#22c55e", "#10b981"];

// Functions
const validateField = (name: string, value: string, formData?: RegisterFormData): string => {
  try {
    switch (name) {
      case "email":
        emailSchema.parse(value);
        return "";
      case "password":
        passwordSchema.parse(value);
        return "";
      case "confirmPassword":
        if (!value) return "Please confirm your password";
        if (formData && value !== formData.password) return "Passwords do not match";
        return "";
      default:
        return "";
    }
  } catch (error) {
    if (error instanceof z.ZodError) {
      return error.issues[0]?.message || "Invalid value";
    }
    return "";
  }
};

const validateForm = (formData: RegisterFormData): ValidationResult => {
  const result = registerSchema.safeParse(formData);

  if (result.success) {
    return { errors: {}, isValid: true };
  }

  const errors: ValidationErrors = {};
  result.error.issues.forEach((err: z.ZodIssue) => {
    const field = err.path[0] as string;
    if (!errors[field]) {
      errors[field] = err.message;
    }
  });

  return { errors, isValid: false };
};

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
export {
  registerSchema,
  loginSchema,
  strengthLabels,
  strengthColors,
  validateField,
  validateForm,
  getPasswordStrength,
};
