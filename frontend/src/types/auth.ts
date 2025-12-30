// Auth Types
interface User {
  id: number;
  email: string;
}

interface Session {
  id: number;
  device: string;
  ip: string;
  userAgent: string;
  createdAt: string;
  expiresAt: string;
  isCurrent: boolean;
}

interface AuthState {
  user: User | null;
  accessToken: string | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  sessions: Session[];
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  logoutAll: () => Promise<void>;
  register: (email: string, password: string) => Promise<void>;
  refresh: () => Promise<boolean>;
  checkAuth: () => Promise<void>;
  getSessions: () => Promise<void>;
  verifyEmail: (token: string) => Promise<void>;
  forgotPassword: (email: string) => Promise<void>;
  resetPassword: (token: string, password: string) => Promise<void>;
  resendVerification: (email: string) => Promise<void>;
}

export type { User, Session, AuthState };
