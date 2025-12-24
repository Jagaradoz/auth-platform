import { Link } from "react-router-dom";

const Footer = () => {
  return (
    <div className="text-center mt-4">
      <p className="text-muted mb-0">
        Don't have an account?{" "}
        <Link to="/register" className="text-decoration-none fw-semibold" style={{ color: "#667eea" }}>
          Sign up
        </Link>
      </p>
    </div>
  );
};

export default Footer;
