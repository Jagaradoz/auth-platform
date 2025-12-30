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

export { UserPayload };
