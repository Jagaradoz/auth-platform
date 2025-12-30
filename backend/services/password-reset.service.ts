import crypto from "crypto";
import { dbRun, dbGet } from "../config/db";
import { PasswordResetToken } from "../types/password-reset-token";

const PASSWORD_RESET_EXPIRY_HOURS = parseInt(process.env.PASSWORD_RESET_EXPIRY_HOURS || "1", 10);
const MS_PER_HOUR = 60 * 60 * 1000;

/** Hash reset token using SHA-256 */
const hashResetToken = (token: string): string => {
  return crypto.createHash("sha256").update(token).digest("hex");
};

/** Create a password reset token for a user */
const createPasswordResetToken = async (userId: number): Promise<string> => {
  // Delete any existing tokens for this user
  await dbRun("DELETE FROM password_reset_tokens WHERE user_id = ?", [userId]);

  // Generate new token
  const plainToken = crypto.randomBytes(32).toString("hex");
  const hashedToken = hashResetToken(plainToken);
  const expiresAt = new Date(Date.now() + PASSWORD_RESET_EXPIRY_HOURS * MS_PER_HOUR).toISOString();

  await dbRun("INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)", [
    userId,
    hashedToken,
    expiresAt,
  ]);

  return plainToken;
};

/** Find password reset token by its hash */
const findPasswordResetTokenByHash = async (
  tokenHash: string,
): Promise<PasswordResetToken | undefined> => {
  return await dbGet<PasswordResetToken>("SELECT * FROM password_reset_tokens WHERE token = ?", [
    tokenHash,
  ]);
};

/** Delete password reset token by ID */
const deletePasswordResetTokenById = async (id: number): Promise<void> => {
  await dbRun("DELETE FROM password_reset_tokens WHERE id = ?", [id]);
};

/** Delete all password reset tokens for a user */
const deletePasswordResetTokensByUserId = async (userId: number): Promise<void> => {
  await dbRun("DELETE FROM password_reset_tokens WHERE user_id = ?", [userId]);
};

export {
  hashResetToken,
  createPasswordResetToken,
  findPasswordResetTokenByHash,
  deletePasswordResetTokenById,
  deletePasswordResetTokensByUserId,
};
