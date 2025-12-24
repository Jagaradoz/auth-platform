interface User {
  id: number;
  email: string;
  password_hash: string;
  created_at: string;
}

interface UserPayload {
  id: number;
  email: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: UserPayload;
    }
  }
}

// Exports
export { User, UserPayload };
