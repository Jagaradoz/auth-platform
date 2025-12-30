import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { UserPayload } from "../types/user-payload";
import logger from "../config/logger";

const JWT_SECRET = process.env.JWT_SECRET!;

/** Verify JWT access token and attach user to request */
const authenticateAccessToken = (req: Request, res: Response, next: NextFunction): void => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    logger.warn("Access denied: No token provided");
    res.status(401).json({ message: "Access denied. No token provided.", code: "NO_TOKEN" });
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as UserPayload;
    req.user = decoded;
    logger.debug(`Access token verified for user: ${decoded.email}`);
    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      logger.warn("Expired access token attempted");
      res.status(401).json({ message: "Access token expired.", code: "TOKEN_EXPIRED" });
    } else {
      logger.warn("Invalid access token attempted");
      res.status(401).json({ message: "Invalid access token.", code: "TOKEN_INVALID" });
    }
    return;
  }
};

export { authenticateAccessToken };
