// Reacts
import { useEffect } from "react";
import { useNavigate } from "react-router-dom";

// Icons
import { LogOut, User, Monitor, Smartphone, Globe, Clock, Trash2 } from "lucide-react";

// Hooks
import useAuth from "../hooks/useAuth";

const Dashboard = () => {
  // Hooks
  const navigate = useNavigate();
  const { user, logout, logoutAll, getSessions, sessions } = useAuth();

  // Effects
  useEffect(() => {
    getSessions();
  }, []);

  // Functions
  const handleLogout = async () => {
    await logout();
    navigate("/login");
  };

  const handleLogoutAll = async () => {
    await logoutAll();
    navigate("/login");
  };

  const getDeviceIcon = (userAgent: string) => {
    const ua = userAgent.toLowerCase();
    if (ua.includes("mobile") || ua.includes("android") || ua.includes("iphone")) {
      return <Smartphone size={20} color="#7c3aed" />;
    }
    return <Monitor size={20} color="#7c3aed" />;
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  return (
    <div className="min-vh-100 bg-section d-flex align-items-center justify-content-center py-5">
      <div style={{ width: "70%", maxWidth: "700px" }}>
        {/* Welcome Heading - Centered above card */}
        <div className="text-center text-white mb-4">
          <h2 className="fw-bold mb-2">Welcome to Dashboard</h2>
          <p className="opacity-75 mb-0">You have successfully logged in to your account.</p>
        </div>

        {/* Card */}
        <div
          className="card border-0"
          style={{
            background: "rgba(255, 255, 255, 0.95)",
            backdropFilter: "blur(10px)",
            boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.4)",
            borderRadius: "16px",
            minHeight: "500px",
          }}
        >
          <div className="card-body p-4 d-flex flex-column" style={{ minHeight: "inherit" }}>
            {/* User Info */}
            <div className="d-flex align-items-center gap-3 mb-4">
              <div
                className="d-flex align-items-center justify-content-center"
                style={{
                  width: "50px",
                  height: "50px",
                  borderRadius: "50%",
                  background: "linear-gradient(135deg, #7c3aed 0%, #0051e6 100%)",
                }}
              >
                <User size={24} color="white" />
              </div>
              <div>
                <p className="mb-0 small text-muted">Logged in as</p>
                <p className="mb-0 fw-semibold" style={{ color: "#1a1a2e" }}>
                  {user?.email}
                </p>
              </div>
            </div>

            {/* Active Sessions */}
            <div className="mb-4">
              <h6 className="fw-semibold mb-3" style={{ color: "#1a1a2e" }}>
                <Globe size={16} className="me-2" style={{ color: "#7c3aed" }} />
                Active Sessions ({sessions.length})
              </h6>

              <div className="d-flex flex-column gap-2">
                {sessions.map((session) => (
                  <div
                    key={session.id}
                    className="d-flex align-items-center justify-content-between p-3 rounded"
                    style={{
                      background: session.isCurrent
                        ? "linear-gradient(135deg, rgba(124, 58, 237, 0.1) 0%, rgba(0, 81, 230, 0.1) 100%)"
                        : "#f8f9fa",
                      border: session.isCurrent
                        ? "1px solid rgba(124, 58, 237, 0.3)"
                        : "1px solid #e9ecef",
                    }}
                  >
                    <div className="d-flex align-items-center gap-3">
                      {getDeviceIcon(session.userAgent)}
                      <div>
                        <p className="mb-0 small fw-medium" style={{ color: "#1a1a2e" }}>
                          {session.device}
                          {session.isCurrent && (
                            <span
                              className="badge ms-2"
                              style={{ background: "#7c3aed", fontSize: "10px" }}
                            >
                              Current
                            </span>
                          )}
                        </p>
                        <p className="mb-0 small text-muted">
                          <Clock size={12} className="me-1" />
                          {formatDate(session.createdAt)} • {session.ip}
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Spacer + Divider + Logout Buttons - Stick to bottom */}
            <div className="mt-auto">
              <hr className="my-4" style={{ borderColor: "#acacacff" }} />

              {/* Logout Buttons */}
              <div className="d-flex justify-content-end gap-2">
                <button
                  onClick={handleLogoutAll}
                  className="btn d-flex align-items-center gap-2"
                  style={{
                    background: "transparent",
                    color: "#dc3545",
                    padding: "10px 20px",
                    fontWeight: 600,
                    border: "1px solid #dc3545",
                    borderRadius: "8px",
                  }}
                >
                  <Trash2 size={16} />
                  Logout All
                </button>
                <button
                  onClick={handleLogout}
                  className="btn d-flex align-items-center gap-2"
                  style={{
                    background: "linear-gradient(135deg, #dc3545 0%, #b31a1a 100%)",
                    color: "white",
                    padding: "10px 24px",
                    fontWeight: 600,
                    border: "none",
                    borderRadius: "8px",
                  }}
                >
                  <LogOut size={18} />
                  Logout
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
