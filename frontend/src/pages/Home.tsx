// Reacts
import { Link } from "react-router-dom";

const Home = () => {
  return (
    <div className="bg-section min-vh-100 d-flex align-items-center">
      <div className="container">
        <div className="row justify-content-center">
          <div className="col-lg-8 col-md-10">
            <div className="text-center">
              {/* Title */}
              <h1
                className="display-4 fw-bold mb-4"
                style={{
                  textShadow: "2px 4px 8px rgba(0, 0, 0, 0.3)",
                }}
              >
                Auth System
              </h1>

              {/* Badges */}
              <div className="mb-4 d-flex flex-wrap justify-content-center gap-2 w-75 mx-auto">
                <span className="badge bg-white bg-opacity-25 px-3 py-2 rounded-pill">
                  <i className="bi bi-lock-fill me-2"></i>Bcrypt Hashing
                </span>
                <span className="badge bg-white bg-opacity-25 px-3 py-2 rounded-pill">
                  <i className="bi bi-key-fill me-2"></i>JWT Tokens
                </span>
                <span className="badge bg-white bg-opacity-25 px-3 py-2 rounded-pill">
                  <i className="bi bi-arrow-repeat me-2"></i>Token Rotation
                </span>
                <span className="badge bg-white bg-opacity-25 px-3 py-2 rounded-pill">
                  <i className="bi bi-envelope-check-fill me-2"></i>Email Verification
                </span>
                <span className="badge bg-white bg-opacity-25 px-3 py-2 rounded-pill">
                  <i className="bi bi-speedometer2 me-2"></i>Rate Limiting
                </span>
                <span className="badge bg-white bg-opacity-25 px-3 py-2 rounded-pill">
                  <i className="bi bi-door-open-fill me-2"></i>Session Management
                </span>
              </div>

              {/* Description */}
              <p className="lead mb-5 opacity-90 w-75 mx-auto">
                A production-style authentication service by{" "}
                <strong className="fw-bold">jagaradoz</strong> demonstrating backend fundamentals,
                realistic auth flows, and baseline security practices.
              </p>

              {/* Buttons */}
              <div className="d-flex justify-content-center gap-3 flex-wrap">
                <Link
                  to="/login"
                  className="btn btn-light px-4 py-2 rounded-pill fw-semibold shadow-sm"
                >
                  <i className="bi bi-box-arrow-in-right me-2"></i>
                  Login
                </Link>

                <Link
                  to="/register"
                  className="btn btn-outline-light px-4 py-2 rounded-pill fw-semibold"
                >
                  <i className="bi bi-person-plus-fill me-2"></i>
                  Register
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Home;
