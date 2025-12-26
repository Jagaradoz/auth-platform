import "dotenv/config";

import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import express, { Express } from "express";

import authRoutes from "../routes/auth.route";
import { initializeDatabase } from "../config/db";
import logger from "../config/logger";
import "../types";

const PORT: number = parseInt(process.env.PORT || "3000", 10);
const app: Express = express();

app.use(helmet());
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

initializeDatabase();

app.use("/api/auth", authRoutes);

app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});

export default app;
