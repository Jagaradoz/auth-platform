import { Router, Request, Response } from "express";
import * as resetService from "../services/reset.service";
import logger from "../config/logger";

const router = Router();

// @route   GET /api/reset
// @desc    Reset database (clear all tables)
// @access  Public but protected by secret key
router.get("/reset", async (req: Request, res: Response): Promise<void> => {
  try {
    const key = req.query.key as string | undefined;

    if (!resetService.validateResetKey(key)) {
      logger.warn("Invalid reset key attempted");
      res.status(403).json({ message: "Invalid reset key" });
      return;
    }

    await resetService.resetDatabase();

    logger.info("Database reset successfully");
    res.json({ message: "Database reset successfully. All data has been cleared." });
  } catch (error) {
    logger.error("Database reset error:", error);
    res.status(500).json({ message: "Server error during database reset" });
  }
});

// @route   GET /api/health
// @desc    Health check endpoint for Render
// @access  Public
router.get("/health", (_req: Request, res: Response): void => {
  res.status(200).json({ status: "ok" });
});

export default router;
