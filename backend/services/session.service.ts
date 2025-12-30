import { dbRun, dbGet, dbAll } from "../config/db";
import { Session } from "../types/session";

/** Create a new session and return the session ID */
const createSession = async (
  userId: number,
  device: string,
  ip: string,
  userAgent: string,
  expiresAt: string,
): Promise<number> => {
  const result = await dbRun(
    "INSERT INTO sessions (user_id, device, ip, user_agent, expires_at) VALUES (?, ?, ?, ?, ?)",
    [userId, device, ip, userAgent, expiresAt],
  );
  return result.lastID;
};

/** Find session by ID */
const findSessionById = async (id: number): Promise<Session | undefined> => {
  return await dbGet<Session>("SELECT * FROM sessions WHERE id = ?", [id]);
};

/** Find active (non-expired) session by ID */
const findActiveSessionById = async (id: number): Promise<Session | undefined> => {
  return await dbGet<Session>(
    "SELECT * FROM sessions WHERE id = ? AND expires_at > datetime('now')",
    [id],
  );
};

/** Find all active sessions for a user */
const findActiveSessionsByUserId = async (userId: number): Promise<Session[]> => {
  return await dbAll<Session>(
    "SELECT id, device, ip, user_agent, created_at, expires_at FROM sessions WHERE user_id = ? AND expires_at > datetime('now')",
    [userId],
  );
};

/** Delete session by ID */
const deleteSessionById = async (id: number): Promise<void> => {
  await dbRun("DELETE FROM sessions WHERE id = ?", [id]);
};

/** Delete all sessions for a user */
const deleteSessionsByUserId = async (userId: number): Promise<void> => {
  await dbRun("DELETE FROM sessions WHERE user_id = ?", [userId]);
};

export {
  createSession,
  findSessionById,
  findActiveSessionById,
  findActiveSessionsByUserId,
  deleteSessionById,
  deleteSessionsByUserId,
};
