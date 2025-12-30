// Reacts
import { useNavigate } from "react-router-dom";
import { useState, ChangeEvent, FormEvent } from "react";

// Components
import Header from "../components/register/Header";
import Footer from "../components/register/Footer";
import Form from "../components/register/Form";

// Hooks
import useAuth from "../hooks/useAuth";

// Services
import { validateField } from "../services/authValidation";

// Constants
import {
  initialFormState,
  initialErrorState,
  initialFeedbackState,
} from "../constants/registerFormDefaults";

// Types
import type { RegisterFormData } from "../types/forms";
import type { ValidationErrors } from "../types/validation";
import type { ApiError } from "../types/api";
import type { FeedbackState } from "../types/ui";

const Register = () => {
  // Hooks
  const navigate = useNavigate();
  const { register } = useAuth();
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [formData, setFormData] = useState<RegisterFormData>(initialFormState);
  const [errors, setErrors] = useState<ValidationErrors>(initialErrorState);
  const [feedback, setFeedback] = useState<FeedbackState>(initialFeedbackState);

  // Functions
  const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    const updatedFormData = { ...formData, [name]: value };
    const fieldError = validateField(name, value, updatedFormData);

    setFormData(updatedFormData);
    setErrors({ ...errors, [name]: fieldError });

    if (feedback.message) setFeedback({ type: null, message: "" });
  };

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    const { email, password, confirmPassword } = formData;

    // Validate all fields
    const emailError = validateField("email", email, formData);
    const passwordError = validateField("password", password, formData);
    const confirmPasswordError = validateField("confirmPassword", confirmPassword, formData);

    setErrors({
      email: emailError,
      password: passwordError,
      confirmPassword: confirmPasswordError,
    });

    if (emailError || passwordError || confirmPasswordError) return;

    setIsLoading(true);
    setFeedback({ type: null, message: "" });

    try {
      await register(formData.email, formData.password);
      navigate("/check-email");
    } catch (error) {
      const apiError = error as ApiError;
      const errorMessage =
        apiError.response?.data?.message ||
        apiError.message ||
        "Registration failed. Please try again.";

      setFeedback({ type: "error", message: errorMessage });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="container-fluid min-vh-100 d-flex align-items-center justify-content-center bg-section">
      <div
        className="card border-0 position-relative"
        style={{
          maxWidth: "450px",
          width: "100%",
          background: "rgba(255, 255, 255, 0.95)",
          backdropFilter: "blur(10px)",
          boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.4)",
        }}
      >
        <div className="card-body p-5">
          <Header />
          <Form
            formData={formData}
            errors={errors}
            isLoading={isLoading}
            feedback={feedback}
            onSubmit={handleSubmit}
            onChange={handleChange}
          />
          <Footer />
        </div>
      </div>
    </div>
  );
};

export default Register;
