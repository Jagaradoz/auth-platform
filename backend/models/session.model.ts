import { dbRun, dbGet, dbAll } from "../config/db";

interface Session {
  id: number;
  user_id: number;
  device: string | null;
  ip: string | null;
  user_agent: string | null;
  created_at: string;
  expires_at: string;
}

/** Create a new session and return the session ID */
const createSessionRecord = async (
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
  Session,
  createSessionRecord,
  findSessionById,
  findActiveSessionById,
  findActiveSessionsByUserId,
  deleteSessionById,
  deleteSessionsByUserId,
};
