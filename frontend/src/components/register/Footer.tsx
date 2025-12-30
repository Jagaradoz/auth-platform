// Reacts
import { Link } from "react-router-dom";

const Footer = () => {
  return (
    <div className="text-center mt-4 pt-3" style={{ borderTop: "1px solid #e9ecef" }}>
      <p className="text-muted mb-0">
        Already have an account?{" "}
        <Link to="/login" className="text-decoration-none fw-semibold" style={{ color: "#667eea" }}>
          Sign in
        </Link>
      </p>
    </div>
  );
};

export default Footer;
