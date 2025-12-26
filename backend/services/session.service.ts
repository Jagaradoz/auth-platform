import {
  Session,
  createSessionRecord,
  findActiveSessionsByUserId,
  deleteSessionById,
  deleteSessionsByUserId,
} from "../models/session.model";

const SESSION_EXPIRY_DAYS = parseInt(process.env.SESSION_EXPIRY_DAYS || "7", 10);

/** Create a new session for user */
const createSession = async (
  userId: number,
  metadata: { device: string; ip: string; userAgent: string },
): Promise<number> => {
  const expiresAt = new Date(Date.now() + SESSION_EXPIRY_DAYS * 24 * 60 * 60 * 1000).toISOString();

  return await createSessionRecord(
    userId,
    metadata.device,
    metadata.ip,
    metadata.userAgent,
    expiresAt,
  );
};

/** Get all active sessions for user */
const getActiveSessions = async (userId: number): Promise<Session[]> => {
  return await findActiveSessionsByUserId(userId);
};

/** Invalidate a session */
const invalidateSession = async (sessionId: number): Promise<void> => {
  await deleteSessionById(sessionId);
};

/** Invalidate all sessions for a user */
const invalidateAllUserSessions = async (userId: number): Promise<void> => {
  await deleteSessionsByUserId(userId);
};

export {
  SESSION_EXPIRY_DAYS,
  createSession,
  getActiveSessions,
  invalidateSession,
  invalidateAllUserSessions,
};
