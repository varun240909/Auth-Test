import express from "express";
import {
  register,
  login,
  refreshToken,
  getMe,
  logout,
  logoutAll,
} from "../controllers/user.controller.js";

import { protect } from "../middleware/auth.middleware.js";
import { validate } from "../middleware/validate.middleware.js";
import { registerSchema, loginSchema } from "../validations/user.validation.js";
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

router.get("/me", protect, getMe);
router.post("/logout", requireCsrf, protect, logout);
router.post("/logout-all", requireCsrf, protect, logoutAll);

export default router;
