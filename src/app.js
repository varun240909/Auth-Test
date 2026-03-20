import express from "express";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import compression from "compression";
import morgan from "morgan";
import { errorHandler } from "./middleware/error.middleware.js";
import userRoutes from "./routes/user.routes.js";

// 1.Initialize Express
const app = express();

const isProduction = process.env.NODE_ENV === "production";

const parseTrustProxy = (value) => {
  const v = String(value).trim().toLowerCase();
  if (v === "true") return true;
  if (v === "false") return false;
  if (/^\d+$/.test(v)) return Number(v);
  return value;
};

if (process.env.TRUST_PROXY !== undefined) {
  app.set("trust proxy", parseTrustProxy(process.env.TRUST_PROXY));
} else if (isProduction) {
  app.set("trust proxy", 1);
}

// 2.Security Middleware
app.use(helmet());

// 3.Enable Cors
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowedOrigins.length === 0) {
        return callback(
          isProduction ? new Error("Not allowed by CORS") : null,
          !isProduction,
        );
      }
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
  }),
);

// 4.Body Parser
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 5.Cookie Parser
app.use(cookieParser());

// 6.Logging
if (process.env.NODE_ENV !== "production") {
  app.use(morgan("dev"));
}

// 7.Compression
app.use(compression());

// 8.Health Check
app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok" });
});

// Routes
app.use("/api/users", userRoutes);

// 9.404 handler for undefined routes
app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

app.use(errorHandler);

export default app;
