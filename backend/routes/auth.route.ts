import { Router } from "express";
import * as authController from "../controllers/auth.controller";
import { authenticateAccessToken } from "../middlewares/auth.middleware";
import { loginLimiter, registerLimiter } from "../middlewares/rateLimiter.middleware";

const router = Router();

router.post("/register", registerLimiter, authController.register);
router.post("/login", loginLimiter, authController.login);
router.post("/logout", authenticateAccessToken, authController.logout);
router.get("/sessions", authenticateAccessToken, authController.getSessions);
router.post("/refresh", authController.refresh);

export default router;
