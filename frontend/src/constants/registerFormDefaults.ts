import type { RegisterFormData, ValidationErrors } from "../types";

// Feedback state type
interface FeedbackState {
  type: "success" | "error" | null;
  message: string;
}

// Register form state
const initialFormState: RegisterFormData = {
  email: "",
  password: "",
  confirmPassword: "",
};

// Error state
const initialErrorState: ValidationErrors = {
  email: "",
  password: "",
  confirmPassword: "",
};

// Feedback state
const initialFeedbackState: FeedbackState = {
  type: null,
  message: "",
};

// Exports
export type { FeedbackState };
export { initialFormState, initialErrorState, initialFeedbackState };
