import express from "express";
import {
  register,
  login,
  refreshToken,
  getMe,
  logout,
  logoutAll,
  resendVerification,
  verifyEmail,
  verifyEmailLink,
} from "../controllers/user.controller.js";

import { protect } from "../middleware/auth.middleware.js";
import { validate } from "../middleware/validate.middleware.js";
import {
  registerSchema,
  loginSchema,
  resendVerificationSchema,
  verifyEmailSchema,
} from "../validations/user.validation.js";
import { requireCsrf, setCsrfCookie } from "../middleware/csrf.middleware.js";
import { createRateLimiter } from "../middleware/rateLimit.middleware.js";

const router = express.Router();

const authLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: "Too many auth attempts, please try again later",
  keyGenerator: (req) => `${req.ip}:${(req.body?.email || "").toLowerCase()}`,
});

const refreshLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: "Too many refresh attempts, please try again later",
});

const verifyLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: "Too many verification attempts, please try again later",
  keyGenerator: (req) => `${req.ip}:${(req.body?.email || "").toLowerCase()}`,
});

router.get("/csrf", (req, res) => {
  const token = setCsrfCookie(req, res);
  res.json({ success: true, csrfToken: token });
});

router.post(
  "/register",
  requireCsrf,
  authLimiter,
  validate(registerSchema),
  register,
);
router.post("/login", requireCsrf, authLimiter, validate(loginSchema), login);
router.post("/refresh", requireCsrf, refreshLimiter, refreshToken);
router.post(
  "/resend-verification",
  requireCsrf,
  verifyLimiter,
  validate(resendVerificationSchema),
  resendVerification,
);
router.post(
  "/verify-email",
  requireCsrf,
  verifyLimiter,
  validate(verifyEmailSchema),
  verifyEmail,
);
router.get("/verify-email", verifyLimiter, verifyEmailLink);

router.get("/me", protect, getMe);
router.post("/logout", requireCsrf, protect, logout);
router.post("/logout-all", requireCsrf, protect, logoutAll);

export default router;
