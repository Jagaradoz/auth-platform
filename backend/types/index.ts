interface User {
  id: number;
  email: string;
  password_hash: string;
  created_at: string;
}

interface Session {
  id: number;
  user_id: number;
  device: string | null;
  ip: string | null;
  user_agent: string | null;
  created_at: string;
  expires_at: string;
}

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

// Exports
export { User, Session, UserPayload };
