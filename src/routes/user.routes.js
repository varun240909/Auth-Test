import express from "express";
import {
  register,
  login,
  refreshToken,
  getMe,
  logout,
} from "../controllers/user.controller.js";

import { protect } from "../middleware/auth.middleware.js";
import { validate } from "../middleware/validate.middleware.js";
import { registerSchema, loginSchema } from "../validations/user.validation.js";

const router = express.Router();

router.post("/register", validate(registerSchema), register);
router.post("/login", validate(loginSchema), login);
router.post("/refresh", refreshToken);

router.get("/me", protect, getMe);
router.post("/logout", logout);

export default router;
