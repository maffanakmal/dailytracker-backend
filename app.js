// OK

import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import helmet from "helmet";

import authRoutes from "./src/routes/auth.route.js";

const app = express();

/**
 * Trust proxy (important for secure cookies behind reverse proxy)
 */
app.set("trust proxy", 1);

/**
 * Security headers
 */
app.use(helmet());

/**
 * CORS configuration
 */
app.use(
  cors({
    origin: process.env.CORS_ORIGINS?.split(","),
    credentials: true,
  })
);

/**
 * Body parsers
 */
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

/**
 * Cookie parser
 */
app.use(cookieParser());

/**
 * Routes
 */
app.use("/api/auth", authRoutes);

/**
 * 404 handler
 */
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Route not found",
  });
});

/**
 * Global error handler
 */
app.use((err, req, res, next) => {
  console.error("GLOBAL ERROR:", err);

  res.status(err.status || 500).json({
    success: false,
    message: err.message || "Internal server error",
  });
});

// install rate limiter

export default app;
