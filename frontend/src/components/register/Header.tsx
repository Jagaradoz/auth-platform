import { UserPlus } from "lucide-react";

const Header = () => {
  return (
    <div className="text-center mb-4">
      <div
        className="d-inline-flex align-items-center justify-content-center rounded-circle mb-3"
        style={{
          width: "64px",
          height: "64px",
          background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
        }}
      >
        <UserPlus size={28} className="text-white" />
      </div>
      <h2 className="fw-bold mb-2" style={{ color: "#1a1a2e" }}>
        Create Account
      </h2>
      <p className="text-muted mb-0">Join us today and get started</p>
    </div>
  );
};

export default Header;
