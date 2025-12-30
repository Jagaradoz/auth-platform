// Types
import type { LoginFormData } from "../types/forms";
import type { ValidationErrors } from "../types/validation";
import type { FeedbackState } from "../types/ui";

// Login form state
const initialFormState: LoginFormData = {
  email: "",
  password: "",
};

// Error state
const initialErrorState: ValidationErrors = {
  email: "",
  password: "",
};

// Feedback state
const initialFeedbackState: FeedbackState = {
  type: null,
  message: "",
};

// Exports
export { initialFormState, initialErrorState, initialFeedbackState };
