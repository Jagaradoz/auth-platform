/** User entity from database */
interface User {
  id: number;
  email: string;
  password_hash: string;
  email_verified: number; // 0 = false, 1 = true (SQLite)
  created_at: string;
}

/** Session entity from database */
interface Session {
  id: number;
  user_id: number;
  device: string | null;
  ip: string | null;
  user_agent: string | null;
  created_at: string;
  expires_at: string;
}

/** Refresh token entity from database */
interface RefreshToken {
  id: number;
  user_id: number;
  token_hash: string;
  session_id: number;
  expires_at: string;
  created_at: string;
}

/** Verification token entity from database */
interface VerificationToken {
  id: number;
  user_id: number;
  token_hash: string;
  expires_at: string;
  created_at: string;
}

/** JWT payload for access tokens */
interface UserPayload {
  id: number;
  email: string;
  sessionId?: number;
}

declare global {
  namespace Express {
    interface Request {
      user?: UserPayload;
    }
  }
}

export { User, Session, RefreshToken, VerificationToken, UserPayload };
