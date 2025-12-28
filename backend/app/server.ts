import "dotenv/config";

import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import express, { Express } from "express";

import logger from "../config/logger";
import initializeDatabase from "../config/db";

import authRoutes from "../routes/auth.route";

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

app.listen(parseInt(process.env.PORT!, 10), () => {
  logger.info(`Server running on port ${process.env.PORT}`);
});

export default app;
