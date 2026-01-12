// Single clean backend bootstrap for mentor-match backend
import express from "express";
import dotenv from "dotenv";
import path from "path";
import cookieParser from "cookie-parser";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import mongoSanitize from "express-mongo-sanitize";
import xss from "xss-clean";

import { connectDB } from "./lib/db.js";
import { app, server } from "./lib/socket.js";

import authRoutes from "./routes/auth.route.js";
import messageRoutes from "./routes/message.route.js";
import mentorRoutes from "./routes/mentor.route.js";
import connectionRoutes from "./routes/connection.route.js";
import geminiRoutes from "./routes/gemini.route.js";
import paymentRoutes from "./routes/payment.route.js";
import perplexityRoutes from "./routes/perplexity.route.js";
import debugRoutes from "./routes/debug.route.js";

dotenv.config();

const PORT = process.env.PORT || 5001;
const __dirname = path.resolve();

// When running behind a proxy (Render, Heroku, Vercel), trust the proxy so
// that Express respects X-Forwarded-* headers (required for rate-limiting and
// to detect secure requests). This prevents express-rate-limit validation errors
// and allows proper secure cookie handling when the proxy terminates TLS.
app.set('trust proxy', true);

// Security middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: false // Disable CSP for now, configure later for production
}));

// Rate limiting - prevent brute force attacks
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 requests per windowMs
  message: { error: "Too many requests from this IP, please try again later" },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per windowMs
  message: { error: "Too many requests, please slow down" },
  standardHeaders: true,
  legacyHeaders: false,
});

// Define trusted origins - include Netlify, Vercel, and local development
const allowedOrigins = [
  process.env.FRONTEND_URL?.replace(/\/$/, ""), // Remove trailing slash if present
  "https://rohitcarreredge.netlify.app",
  "https://carreredge.onrender.com",
  "https://careeredgee.netlify.app",
  "https://careeredge.netlify.app",
  "http://localhost:5173",
  "http://127.0.0.1:5173"
].filter(Boolean);

// Also allow all Vercel preview deployments
const vercelPattern = /https:\/\/carrer-edge.*\.vercel\.app$/;

// CORS configuration with origin checking
const corsOptions = {
  origin: function (origin, callback) {
    // Allow server-to-server requests (no origin)
    if (!origin) {
      return callback(null, true);
    }

    // Check against allowed origins and Vercel pattern
    if (allowedOrigins.includes(origin) || vercelPattern.test(origin)) {
      callback(null, true);
    } else {
      console.log("Blocked CORS origin:", origin, "Allowed:", allowedOrigins);
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "X-Requested-With",
    "Cookie",
    "Accept",
    "Origin"
  ],
  exposedHeaders: ["Set-Cookie"],
};

// Apply CORS middleware
app.use(cors(corsOptions));

// Allow larger JSON payloads to support base64 image uploads from the frontend
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ limit: "10mb", extended: true }));
app.use(cookieParser());

// Data sanitization against NoSQL query injection
app.use(mongoSanitize());

// Data sanitization against XSS
app.use(xss());

// Simple request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - Origin: ${req.headers.origin || "No Origin"}`);
  next();
});

// Health
app.get("/api/health", (req, res) => res.status(200).json({
  status: "OK",
  env: process.env.NODE_ENV || "development",
  corsOrigins: [...allowedOrigins, "(and all https://*.vercel.app deployments)"]
}));

// Debug endpoints (temporary) - exposes non-sensitive env flags and cookie checks
app.use("/api/debug", apiLimiter, debugRoutes);

// Register API routes with rate limiting
app.use("/api/auth", authLimiter, authRoutes);
app.use("/api/messages", apiLimiter, messageRoutes);
app.use("/api/mentorship", apiLimiter, mentorRoutes);
app.use("/api/gemini", apiLimiter, geminiRoutes);
app.use("/api/payments", authLimiter, paymentRoutes);
app.use("/api/discover", apiLimiter, perplexityRoutes);
app.use("/api/connections", apiLimiter, connectionRoutes);

// 404 handler for API routes - must come AFTER all other routes
app.use((req, res, next) => {
  // Only handle /api/* routes here
  if (req.path.startsWith("/api/")) {
    console.log("404 - API endpoint not found:", req.method, req.path);
    return res.status(404).json({
      message: "API endpoint not found",
      path: req.path
    });
  }
  next();
});

// Health check for root path
app.get("/", (req, res) => {
  res.json({
    status: "OK",
    message: "CareerEdge API Server",
    frontend: "https://rohitcarreredge.netlify.app",
    docs: "/api/health"
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("Global error:", err && err.stack ? err.stack : err);
  // Check if it's a rate limit error
  if (err.status === 429 || err.message.includes("Too many requests")) {
    console.log("Rate limit error:", err.message);
    return res.status(429).json({ message: err.message || "Too many requests" });
  }
  res.status(err.status || 500).json({ message: err.message || "Internal Server Error" });
});

server.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
  console.log("Allowed CORS origins:", [
    ...allowedOrigins,
    "(and all https://*.vercel.app deployments)"
  ]);
  connectDB();
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  console.error('?? UNHANDLED REJECTION! Shutting down...');
  console.error(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('?? UNCAUGHT EXCEPTION! Shutting down...');
  console.error(err.name, err.message);
  process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('?? SIGTERM received. Shutting down gracefully');
  server.close(() => {
    console.log('?? Process terminated');
  });
});

export default app;
