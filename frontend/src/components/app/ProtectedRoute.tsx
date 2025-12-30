// Reacts
import { useEffect, useRef } from "react";
import { Navigate, Outlet } from "react-router-dom";

// Hooks
import useAuth from "../../hooks/useAuth";

const ProtectedRoute = () => {
  // Hooks
  const { isAuthenticated, isLoading, checkAuth } = useAuth();
  const hasChecked = useRef(false);

  // Effects
  useEffect(() => {
    if (!hasChecked.current) {
      hasChecked.current = true;
      checkAuth();
    }
  }, [checkAuth]);

  if (isLoading) {
    return (
      <div className="min-vh-100 d-flex align-items-center justify-content-center bg-section">
        <div className="spinner-border text-light" role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
};

export default ProtectedRoute;
