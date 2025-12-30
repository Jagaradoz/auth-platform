// Types
import type { RegisterFormData } from "../types/forms";
import type { ValidationErrors } from "../types/validation";
import type { FeedbackState } from "../types/ui";

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
export { initialFormState, initialErrorState, initialFeedbackState };
