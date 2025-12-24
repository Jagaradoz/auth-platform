// Reacts
import { useState, ChangeEvent, FormEvent } from "react";
import { useNavigate } from "react-router-dom";

// Components
import Header from "../components/login/Header";
import Footer from "../components/login/Footer";
import Form from "../components/login/Form";

// Constants
import {
  initialFormState,
  initialFeedbackState,
  FeedbackState,
} from "../constants/loginFormDefaults";

// Types
import type { LoginFormData, ApiError } from "../types";

const Login = () => {
  // Hooks
  const navigate = useNavigate();
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [formData, setFormData] = useState<LoginFormData>(initialFormState);
  const [feedback, setFeedback] = useState<FeedbackState>(initialFeedbackState);

  // Functions
  const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    setIsLoading(true);
    setFeedback({ type: null, message: "" });

    try {
      // TODO: Replace with actual API call
      // const response = await axios.post('/api/auth/login', {
      //   email: formData.email,
      //   password: formData.password,
      // });

      // Simulate API call - throw error to test error message
      await new Promise((resolve) => setTimeout(resolve, 2000));

      // Redirect to dashboard on success
      navigate("/dashboard");
    } catch (error) {
      const apiError = error as ApiError;
      const errorMessage =
        apiError.response?.data?.message || apiError.message || "Invalid email or password";
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

export default Login;
