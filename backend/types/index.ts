import { UserPayload } from "../services/token.service";

declare global {
  namespace Express {
    interface Request {
      user?: UserPayload;
    }
  }
}

export {};
