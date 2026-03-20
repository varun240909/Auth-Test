import crypto from "crypto";
import User from "../models/User.model.js";
import RefreshSession from "../models/RefreshSession.model.js";
import ApiError from "../utils/ApiError.js";
import { isEmailConfigured, sendVerificationEmail } from "../services/email.service.js";
import {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
} from "../utils/token.js";
import {
  accessCookieOptions,
  refreshCookieOptions,
  clearAccessCookieOptions,
  clearRefreshCookieOptions,
} from "../utils/cookie.js";

const isProduction = process.env.NODE_ENV === "production";
const EMAIL_VERIFICATION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

const hashSha256 = (value) =>
  crypto.createHash("sha256").update(String(value)).digest("hex");

const hashToken = (token) =>
  hashSha256(token);

const timingSafeEqual = (a, b) => {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
};

const createEmailVerificationToken = () => {
  const token = crypto.randomBytes(32).toString("hex");
  return {
    token,
    tokenHash: hashSha256(token),
    expiresAt: new Date(Date.now() + EMAIL_VERIFICATION_TTL_MS),
  };
};

const maybeSendVerificationEmail = async ({ email, token }) => {
  if (!isEmailConfigured()) {
    if (!isProduction) {
      console.warn(
        "Email not configured; returning verification token in response (dev only).",
      );
    }
    return;
  }

  try {
    await sendVerificationEmail({ to: email, token });
  } catch (err) {
    console.error("Failed to send verification email:", err?.message || err);
  }
};

const newSessionId = () =>
  typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : crypto.randomBytes(16).toString("hex");

const getSessionMetadata = (req) => ({
  userAgent: req.get("user-agent") || null,
  ip: req.ip || null,
});

export const register = async (req, res, next) => {
  try {
    const verification = createEmailVerificationToken();

    const user = await User.create({
      ...req.body,
      role: "user",
      isVerified: false,
      emailVerificationTokenHash: verification.tokenHash,
      emailVerificationTokenExpiresAt: verification.expiresAt,
    });

    await maybeSendVerificationEmail({
      email: user.email,
      token: verification.token,
    });

    res.status(201).json({
      success: true,
      message: "Registration successful. Verify your email to continue.",
      user,
      ...(isProduction ? {} : { emailVerificationToken: verification.token }),
    });
  } catch (err) {
    next(err);
  }
};

export const login = async (req, res, next) => {
  try {
    const user = await User.findOne({ email: req.body.email }).select(
      "+password",
    );

    if (!user || !(await user.comparePassword(req.body.password))) {
      throw new ApiError(401, "Invalid credentials");
    }

    if (!user.isVerified) {
      throw new ApiError(403, "Account not verified");
    }

    const sessionId = newSessionId();
    const accessToken = generateAccessToken(user, { sessionId });
    const refreshToken = generateRefreshToken(user, sessionId);

    const refreshDecoded = verifyRefreshToken(refreshToken);
    await RefreshSession.create({
      user: user._id,
      sessionId,
      refreshTokenHash: hashToken(refreshToken),
      lastUsedAt: new Date(),
      expiresAt: new Date((refreshDecoded.exp || 0) * 1000),
      ...getSessionMetadata(req),
    });

    res.cookie("accessToken", accessToken, accessCookieOptions);
    res.cookie("refreshToken", refreshToken, refreshCookieOptions);

    res.json({
      success: true,
      user,
    });
  } catch (err) {
    next(err);
  }
};

export const refreshToken = async (req, res, next) => {
  try {
    const token = req.cookies.refreshToken;

    if (!token) {
      throw new ApiError(401, "No refresh token");
    }
    const decoded = verifyRefreshToken(token);

    const user = await User.findById(decoded.id);
    if (!user) throw new ApiError(401, "User not found");

    if (!user.isVerified) {
      res.clearCookie("accessToken", clearAccessCookieOptions);
      res.clearCookie("refreshToken", clearRefreshCookieOptions);
      throw new ApiError(403, "Account not verified");
    }

    if (
      decoded?.tokenVersion === undefined ||
      decoded.tokenVersion !== user.tokenVersion
    ) {
      throw new ApiError(401, "Token revoked");
    }

    if (!decoded?.sid) {
      throw new ApiError(401, "Invalid refresh token");
    }

    const session = await RefreshSession.findOne({
      user: user._id,
      sessionId: decoded.sid,
    });

    const now = new Date();
    if (!session || session.revokedAt || session.expiresAt <= now) {
      res.clearCookie("accessToken", clearAccessCookieOptions);
      res.clearCookie("refreshToken", clearRefreshCookieOptions);
      throw new ApiError(401, "Invalid refresh session");
    }

    const presentedHash = hashToken(token);
    if (!timingSafeEqual(presentedHash, session.refreshTokenHash)) {
      session.revokedAt = now;
      await session.save();

      await User.findByIdAndUpdate(user._id, { $inc: { tokenVersion: 1 } });

      res.clearCookie("accessToken", clearAccessCookieOptions);
      res.clearCookie("refreshToken", clearRefreshCookieOptions);

      return res.status(403).json({
        success: false,
        message: "Token reuse detected. Please log in again.",
      });
    }

    const newAccessToken = generateAccessToken(user, { sessionId: decoded.sid });
    const newRefreshToken = generateRefreshToken(user, decoded.sid);

    const refreshDecoded = verifyRefreshToken(newRefreshToken);
    session.refreshTokenHash = hashToken(newRefreshToken);
    session.lastUsedAt = now;
    session.expiresAt = new Date((refreshDecoded.exp || 0) * 1000);
    await session.save();

    res.cookie("accessToken", newAccessToken, accessCookieOptions);
    res.cookie("refreshToken", newRefreshToken, refreshCookieOptions);

    return res.json({
      success: true,
      user,
    });
  } catch (err) {
    next(err);
  }
};

export const getMe = async (req, res) => {
  res.json({
    success: true,
    user: req.user,
  });
};

export const logout = async (req, res, next) => {
  try {
    const token = req.cookies?.refreshToken;
    if (token) {
      try {
        const decoded = verifyRefreshToken(token);
        if (String(decoded.id) === String(req.user._id) && decoded.sid) {
          await RefreshSession.findOneAndUpdate(
            { user: req.user._id, sessionId: decoded.sid, revokedAt: null },
            { $set: { revokedAt: new Date() } },
          );
        }
      } catch {
        // ignore invalid refresh token on logout
      }
    }
  } catch (err) {
    return next(err);
  }

  res.clearCookie("accessToken", clearAccessCookieOptions);
  res.clearCookie("refreshToken", clearRefreshCookieOptions);

  res.json({
    success: true,
    message: "Logged out",
  });
};

export const logoutAll = async (req, res, next) => {
  try {
    req.user.tokenVersion += 1;
    await req.user.save();

    await RefreshSession.updateMany(
      { user: req.user._id, revokedAt: null },
      { $set: { revokedAt: new Date() } },
    );
  } catch (err) {
    return next(err);
  }

  res.clearCookie("accessToken", clearAccessCookieOptions);
  res.clearCookie("refreshToken", clearRefreshCookieOptions);

  res.json({
    success: true,
    message: "Logged out from all sessions",
  });
};

export const resendVerification = async (req, res, next) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();

    const user = await User.findOne({ email });

    if (!user) {
      return res.json({
        success: true,
        message: "If the account exists, a verification email has been sent.",
      });
    }

    if (user.isVerified) {
      return res.json({ success: true, message: "Account already verified" });
    }

    const verification = createEmailVerificationToken();
    user.emailVerificationTokenHash = verification.tokenHash;
    user.emailVerificationTokenExpiresAt = verification.expiresAt;
    await user.save();

    await maybeSendVerificationEmail({
      email: user.email,
      token: verification.token,
    });

    return res.json({
      success: true,
      message: "Verification token created",
      ...(isProduction ? {} : { emailVerificationToken: verification.token }),
    });
  } catch (err) {
    next(err);
  }
};

const verifyEmailToken = async ({ email, token }) => {
  const normalizedEmail = String(email || "").trim().toLowerCase();
  const presentedToken = String(token || "");

  const user = await User.findOne({ email: normalizedEmail }).select(
    "+emailVerificationTokenHash +emailVerificationTokenExpiresAt",
  );
  if (!user) throw new ApiError(400, "Invalid verification token");

  if (user.isVerified) {
    return { alreadyVerified: true };
  }

  const now = new Date();
  if (
    !user.emailVerificationTokenHash ||
    !user.emailVerificationTokenExpiresAt ||
    user.emailVerificationTokenExpiresAt <= now
  ) {
    throw new ApiError(400, "Verification token expired");
  }

  const presentedHash = hashSha256(presentedToken);
  if (!timingSafeEqual(presentedHash, user.emailVerificationTokenHash)) {
    throw new ApiError(400, "Invalid verification token");
  }

  user.isVerified = true;
  user.emailVerificationTokenHash = undefined;
  user.emailVerificationTokenExpiresAt = undefined;
  await user.save();

  return { verified: true };
};

export const verifyEmail = async (req, res, next) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const token = String(req.body?.token || "");

    const result = await verifyEmailToken({ email, token });
    if (result.alreadyVerified) {
      return res.json({ success: true, message: "Account already verified" });
    }
    return res.json({ success: true, message: "Email verified" });
  } catch (err) {
    next(err);
  }
};

export const verifyEmailLink = async (req, res, next) => {
  try {
    const email = String(req.query?.email || "").trim().toLowerCase();
    const token = String(req.query?.token || "");

    const result = await verifyEmailToken({ email, token });
    if (result.alreadyVerified) {
      return res.status(200).json({ success: true, message: "Already verified" });
    }

    return res.status(200).json({ success: true, message: "Email verified" });
  } catch (err) {
    next(err);
  }
};
