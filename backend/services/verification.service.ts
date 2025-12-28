import crypto from "crypto";
import { dbRun, dbGet } from "../config/db";
import { VerificationToken } from "../types";

const VERIFICATION_TOKEN_EXPIRY_HOURS = parseInt(process.env.VERIFICATION_TOKEN_EXPIRY_HOURS!, 10);

/** Hash verification token using SHA-256 */
const hashVerificationToken = (token: string): string => {
  return crypto.createHash("sha256").update(token).digest("hex");
};

/** Generate a random verification token */
const generateVerificationToken = (): string => {
  return crypto.randomBytes(32).toString("hex");
};

/** Create a verification token for a user */
const createVerificationToken = async (userId: number): Promise<string> => {
  // Delete any existing tokens for this user
  await dbRun("DELETE FROM verification_tokens WHERE user_id = ?", [userId]);

  // Generate new token
  const token = generateVerificationToken();
  const tokenHash = hashVerificationToken(token);
  const expiresAt = new Date(
    Date.now() + VERIFICATION_TOKEN_EXPIRY_HOURS * 60 * 60 * 1000,
  ).toISOString();

  await dbRun(
    "INSERT INTO verification_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
    [userId, tokenHash, expiresAt],
  );

  return token; // Return plain token to send via email
};

/** Find verification token by its hash */
const findVerificationTokenByHash = async (
  tokenHash: string,
): Promise<VerificationToken | undefined> => {
  return await dbGet<VerificationToken>("SELECT * FROM verification_tokens WHERE token_hash = ?", [
    tokenHash,
  ]);
};

/** Delete verification token by ID */
const deleteVerificationTokenById = async (id: number): Promise<void> => {
  await dbRun("DELETE FROM verification_tokens WHERE id = ?", [id]);
};

/** Delete all verification tokens for a user */
const deleteVerificationTokensByUserId = async (userId: number): Promise<void> => {
  await dbRun("DELETE FROM verification_tokens WHERE user_id = ?", [userId]);
};

/** Mark user as verified */
const markUserAsVerified = async (userId: number): Promise<void> => {
  await dbRun("UPDATE users SET email_verified = 1 WHERE id = ?", [userId]);
};

export {
  hashVerificationToken,
  generateVerificationToken,
  createVerificationToken,
  findVerificationTokenByHash,
  deleteVerificationTokenById,
  deleteVerificationTokensByUserId,
  markUserAsVerified,
};
