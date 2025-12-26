import { dbRun, dbGet } from "../config/db";

interface RefreshToken {
  id: number;
  user_id: number;
  token_hash: string;
  session_id: number;
  expires_at: string;
  created_at: string;
}

/** Create a new refresh token and return the token ID */
const createRefreshToken = async (
  userId: number,
  tokenHash: string,
  sessionId: number,
  expiresAt: string,
): Promise<number> => {
  const result = await dbRun(
    "INSERT INTO refresh_tokens (user_id, token_hash, session_id, expires_at) VALUES (?, ?, ?, ?)",
    [userId, tokenHash, sessionId, expiresAt],
  );
  return result.lastID;
};

/** Find refresh token by its hash */
const findRefreshTokenByHash = async (tokenHash: string): Promise<RefreshToken | undefined> => {
  return await dbGet<RefreshToken>("SELECT * FROM refresh_tokens WHERE token_hash = ?", [
    tokenHash,
  ]);
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

export {
  RefreshToken,
  createRefreshToken,
  findRefreshTokenByHash,
  deleteRefreshTokenById,
  deleteRefreshTokensBySessionId,
  deleteRefreshTokensByUserId,
};
