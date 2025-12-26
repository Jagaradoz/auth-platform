import bcrypt from "bcryptjs";
import { User, findUserById, findUserByEmail, createUser } from "../models/user.model";
import { findActiveSessionById } from "../models/session.model";
import { findRefreshTokenByHash, deleteRefreshTokenById } from "../models/refreshToken.model";
import { createSession } from "./session.service";
import { hashRefreshToken } from "./token.service";
import logger from "../config/logger";

/** Register a new user */
const registerUser = async (email: string, password: string): Promise<{ userId: number }> => {
  const existingUser = await findUserByEmail(email);
  if (existingUser) {
    throw new Error("User with this email already exists");
  }

  const salt = await bcrypt.genSalt(10);
  const passwordHash = await bcrypt.hash(password, salt);
  const userId = await createUser(email, passwordHash);

  logger.info(`New user registered: ${email} (ID: ${userId})`);
  return { userId };
};

/** Authenticate user credentials and create session */
const authenticateUser = async (
  email: string,
  password: string,
  metadata: { device: string; ip: string; userAgent: string },
): Promise<{ user: User; sessionId: number }> => {
  const user = await findUserByEmail(email);
  if (!user) {
    throw new Error("Invalid credentials");
  }

  const isMatch = await bcrypt.compare(password, user.password_hash);
  if (!isMatch) {
    throw new Error("Invalid credentials");
  }

  const sessionId = await createSession(user.id, metadata);

  logger.info(`User logged in successfully: ${email} (Session: ${sessionId})`);
  return { user, sessionId };
};

/** Validate refresh token and get associated user/session */
const validateRefreshToken = async (
  refreshToken: string,
): Promise<{ user: User; sessionId: number; storedTokenId: number } | null> => {
  const tokenHash = hashRefreshToken(refreshToken);

  const storedToken = await findRefreshTokenByHash(tokenHash);
  if (!storedToken) {
    logger.warn("Invalid refresh token attempted");
    return null;
  }

  if (new Date(storedToken.expires_at) < new Date()) {
    await deleteRefreshTokenById(storedToken.id);
    logger.warn("Expired refresh token attempted");
    return null;
  }

  const session = await findActiveSessionById(storedToken.session_id);
  if (!session) {
    await deleteRefreshTokenById(storedToken.id);
    logger.warn("Refresh token for expired session attempted");
    return null;
  }

  const user = await findUserById(storedToken.user_id);
  if (!user) {
    await deleteRefreshTokenById(storedToken.id);
    logger.warn("Refresh token for non-existent user attempted");
    return null;
  }

  return { user, sessionId: storedToken.session_id, storedTokenId: storedToken.id };
};

export { registerUser, authenticateUser, validateRefreshToken };
