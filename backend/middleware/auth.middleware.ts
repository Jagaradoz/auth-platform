import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { UserPayload } from "../types";
import logger from "../utils/logger";

const JWT_SECRET = process.env.JWT_SECRET || "your-super-secret-jwt-key";

/** Verify JWT token and attach user to request */
const authenticateToken = (req: Request, res: Response, next: NextFunction): void => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

  if (!token) {
    logger.warn("Access denied: No token provided");
    res.status(401).json({ message: "Access denied. No token provided." });
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as UserPayload;
    req.user = decoded;
    logger.debug(`Token verified for user: ${decoded.email}`);
    next();
  } catch (error) {
    logger.warn("Invalid or expired token attempted");
    res.status(403).json({ message: "Invalid or expired token." });
    return;
  }
};

/** Generate JWT access token */
const generateToken = (user: UserPayload): string => {
  logger.debug(`Generating token for user: ${user.email}`);
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
    expiresIn: "1h",
  });
};

// Exports
export { authenticateToken, generateToken, JWT_SECRET };
