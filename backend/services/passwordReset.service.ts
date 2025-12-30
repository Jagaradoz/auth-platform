import crypto from "crypto";
import { dbRun, dbGet } from "../config/db";

const PASSWORD_RESET_EXPIRY_HOURS = parseInt(process.env.PASSWORD_RESET_EXPIRY_HOURS || "1", 10);

interface PasswordResetToken {
  id: number;
  user_id: number;
  token_hash: string;
  expires_at: string;
  created_at: string;
}

/** Hash reset token using SHA-256 */
const hashResetToken = (token: string): string => {
  return crypto.createHash("sha256").update(token).digest("hex");
};

/** Generate a random reset token */
const generateResetToken = (): string => {
  return crypto.randomBytes(32).toString("hex");
};

/** Create a password reset token for a user */
const createPasswordResetToken = async (userId: number): Promise<string> => {
  // Delete any existing tokens for this user
  await dbRun("DELETE FROM password_reset_tokens WHERE user_id = ?", [userId]);

  // Generate new token
  const token = generateResetToken();
  const tokenHash = hashResetToken(token);
  const expiresAt = new Date(
    Date.now() + PASSWORD_RESET_EXPIRY_HOURS * 60 * 60 * 1000,
  ).toISOString();

  await dbRun(
    "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
    [userId, tokenHash, expiresAt],
  );

  return token;
};

/** Find password reset token by its hash */
const findPasswordResetTokenByHash = async (
  tokenHash: string,
): Promise<PasswordResetToken | undefined> => {
  return await dbGet<PasswordResetToken>(
    "SELECT * FROM password_reset_tokens WHERE token_hash = ?",
    [tokenHash],
  );
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
  generateResetToken,
  createPasswordResetToken,
  findPasswordResetTokenByHash,
  deletePasswordResetTokenById,
  deletePasswordResetTokensByUserId,
};
