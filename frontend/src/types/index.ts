// Form Data Types
interface RegisterFormData {
  email: string;
  password: string;
  confirmPassword: string;
}

interface LoginFormData {
  email: string;
  password: string;
}

// Validation Error Types
type ValidationErrors = {
  [key: string]: string;
};

interface ValidationResult {
  errors: ValidationErrors;
  isValid: boolean;
}

// API Error Types
interface ApiError {
  response?: {
    data?: {
      message?: string;
    };
  };
  message?: string;
}

// Exports
export type { RegisterFormData, LoginFormData, ValidationErrors, ValidationResult, ApiError };
