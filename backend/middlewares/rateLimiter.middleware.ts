import rateLimit from "express-rate-limit";

/** Rate limiter for login: 50 attempts per 15 minutes */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { message: "Too many login attempts. Please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

/** Rate limiter for register: 50 accounts per hour */
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 50,
  message: { message: "Too many accounts created. Please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

export { loginLimiter, registerLimiter };
