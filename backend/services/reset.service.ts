import { dbRun } from "../config/db";
import logger from "../config/logger";

const RESET_SECRET = process.env.RESET_SECRET;

const validateResetKey = (key: string | undefined): boolean => {
  if (!RESET_SECRET) {
    logger.warn("RESET_SECRET not configured");
    return false;
  }
  return key === RESET_SECRET;
};

const resetDatabase = async (): Promise<void> => {
  await dbRun("DELETE FROM password_reset_tokens");
  await dbRun("DELETE FROM email_verification_tokens");
  await dbRun("DELETE FROM refresh_tokens");
  await dbRun("DELETE FROM sessions");
  await dbRun("DELETE FROM users");

  logger.info("Database reset: all tables cleared");
};

export { validateResetKey, resetDatabase };
