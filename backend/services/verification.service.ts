import crypto from "crypto";
import { dbRun, dbGet } from "../config/db";
import { VerificationToken } from "../types/verification-token";

const VERIFICATION_TOKEN_EXPIRY_HOURS = parseInt(process.env.VERIFICATION_TOKEN_EXPIRY_HOURS!, 10);
const MS_PER_HOUR = 60 * 60 * 1000;

/** Hash verification token using SHA-256 */
const hashVerificationToken = (token: string): string => {
  return crypto.createHash("sha256").update(token).digest("hex");
};

/** Create a verification token for a user */
const createVerificationToken = async (userId: number): Promise<string> => {
  // Delete any existing tokens for this user
  await dbRun("DELETE FROM email_verification_tokens WHERE user_id = ?", [userId]);

  // Generate new token
  const plainToken = crypto.randomBytes(32).toString("hex");
  const hashedToken = hashVerificationToken(plainToken);
  const expiresAt = new Date(
    Date.now() + VERIFICATION_TOKEN_EXPIRY_HOURS * MS_PER_HOUR,
  ).toISOString();

  await dbRun(
    "INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
    [userId, hashedToken, expiresAt],
  );

  return plainToken;
};

/** Find verification token by its hash */
const findVerificationTokenByHash = async (
  tokenHash: string,
): Promise<VerificationToken | undefined> => {
  return await dbGet<VerificationToken>("SELECT * FROM email_verification_tokens WHERE token = ?", [
    tokenHash,
  ]);
};

/** Delete verification token by ID */
const deleteVerificationTokenById = async (id: number): Promise<void> => {
  await dbRun("DELETE FROM email_verification_tokens WHERE id = ?", [id]);
};

/** Delete all verification tokens for a user */
const deleteVerificationTokensByUserId = async (userId: number): Promise<void> => {
  await dbRun("DELETE FROM email_verification_tokens WHERE user_id = ?", [userId]);
};

/** Mark user as verified */
const markUserAsVerified = async (userId: number): Promise<void> => {
  await dbRun("UPDATE users SET email_verified = 1 WHERE id = ?", [userId]);
};

export {
  hashVerificationToken,
  createVerificationToken,
  findVerificationTokenByHash,
  deleteVerificationTokenById,
  deleteVerificationTokensByUserId,
  markUserAsVerified,
};
