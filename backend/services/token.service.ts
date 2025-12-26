import { Response } from "express";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { createRefreshToken } from "../models/refreshToken.model";
import logger from "../config/logger";

interface UserPayload {
  id: number;
  email: string;
  sessionId?: number;
}

const JWT_SECRET = process.env.JWT_SECRET || "jwtSecret";
const ACCESS_TOKEN_EXPIRY_TIME = process.env.ACCESS_TOKEN_EXPIRY_TIME || "1h";
const REFRESH_TOKEN_EXPIRY_DAYS = parseInt(process.env.REFRESH_TOKEN_EXPIRY_DAYS || "7", 10);

/** Generate cryptographically secure refresh token */
const generateRefreshToken = (): string => {
  return crypto.randomBytes(32).toString("hex");
};

/** Hash refresh token using SHA-256 for secure storage */
const hashRefreshToken = (token: string): string => {
  return crypto.createHash("sha256").update(token).digest("hex");
};

/** Generate JWT access token */
const generateAccessToken = (user: UserPayload): string => {
  logger.debug(`Generating access token for user: ${user.email}`);
  return jwt.sign({ id: user.id, email: user.email, sessionId: user.sessionId }, JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRY_TIME as jwt.SignOptions["expiresIn"],
  });
};

/** Issue refresh token - generates, stores in DB, sets cookie */
const issueRefreshToken = async (
  res: Response,
  userId: number,
  sessionId: number,
): Promise<void> => {
  const refreshToken = generateRefreshToken();
  const refreshTokenHash = hashRefreshToken(refreshToken);
  const expiresAt = new Date(
    Date.now() + REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60 * 1000,
  ).toISOString();

  await createRefreshToken(userId, refreshTokenHash, sessionId, expiresAt);

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60 * 1000,
  });
};

/** Clear refresh token cookie */
const clearRefreshTokenCookie = (res: Response): void => {
  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
  });
};

export {
  UserPayload,
  JWT_SECRET,
  REFRESH_TOKEN_EXPIRY_DAYS,
  generateRefreshToken,
  hashRefreshToken,
  generateAccessToken,
  issueRefreshToken,
  clearRefreshTokenCookie,
};
