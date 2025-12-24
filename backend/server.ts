// Dotenv
import "dotenv/config";

// Packages
import cors from "cors";
import helmet from "helmet";
import express, { Express } from "express";

// Routes
import authRoutes from "./routes/auth.route";

// Utils
import { initializeDatabase } from "./utils/db";
import logger from "./utils/logger";

// Types
import "./types";

// Constants
const PORT: number = parseInt(process.env.PORT || "3000", 10);

// Variables
const app: Express = express();

// Middleware
app.use(helmet());
app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);
app.use(express.json());

// Initialize database tables
initializeDatabase();

// Routes
app.use("/api/auth", authRoutes);

// Listening
app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});

export default app;
