import { Response } from "express";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { dbRun, dbGet } from "../config/db";
import { RefreshToken } from "../types/refresh-token";
import { UserPayload } from "../types/user-payload";
import logger from "../config/logger";

const JWT_SECRET = process.env.JWT_SECRET!;
const ACCESS_TOKEN_EXPIRY_TIME = process.env.ACCESS_TOKEN_EXPIRY_TIME!;
const REFRESH_TOKEN_EXPIRY_DAYS = parseInt(process.env.REFRESH_TOKEN_EXPIRY_DAYS!, 10);
const MS_PER_DAY = 24 * 60 * 60 * 1000;

/** Generate JWT access token */
const generateAccessToken = (user: UserPayload): string => {
  logger.debug(`Generating access token for user: ${user.email}`);
  return jwt.sign({ id: user.id, email: user.email, sessionId: user.sessionId }, JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRY_TIME as jwt.SignOptions["expiresIn"],
  });
};

/** Hash refresh token using SHA-256 for secure storage */
const hashRefreshToken = (token: string): string => {
  return crypto.createHash("sha256").update(token).digest("hex");
};

/** Create refresh token - generates, stores in DB, sets cookie */
const createRefreshToken = async (
  res: Response,
  userId: number,
  sessionId: number,
): Promise<void> => {
  const plainToken = crypto.randomBytes(32).toString("hex");
  const hashedToken = hashRefreshToken(plainToken);
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_EXPIRY_DAYS * MS_PER_DAY).toISOString();

  await dbRun(
    "INSERT INTO refresh_tokens (user_id, token, session_id, expires_at) VALUES (?, ?, ?, ?)",
    [userId, hashedToken, sessionId, expiresAt],
  );

  res.cookie("refreshToken", plainToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: REFRESH_TOKEN_EXPIRY_DAYS * MS_PER_DAY,
  });
};

/** Find refresh token by its hash */
const findRefreshTokenByHash = async (tokenHash: string): Promise<RefreshToken | undefined> => {
  return await dbGet<RefreshToken>("SELECT * FROM refresh_tokens WHERE token = ?", [tokenHash]);
};

/** Delete refresh token by ID */
const deleteRefreshTokenById = async (id: number): Promise<void> => {
  await dbRun("DELETE FROM refresh_tokens WHERE id = ?", [id]);
};

/** Delete all refresh tokens for a session */
const deleteRefreshTokensBySessionId = async (sessionId: number): Promise<void> => {
  await dbRun("DELETE FROM refresh_tokens WHERE session_id = ?", [sessionId]);
};

/** Delete all refresh tokens for a user */
const deleteRefreshTokensByUserId = async (userId: number): Promise<void> => {
  await dbRun("DELETE FROM refresh_tokens WHERE user_id = ?", [userId]);
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
  generateAccessToken,
  hashRefreshToken,
  createRefreshToken,
  findRefreshTokenByHash,
  deleteRefreshTokenById,
  deleteRefreshTokensBySessionId,
  deleteRefreshTokensByUserId,
  clearRefreshTokenCookie,
};
