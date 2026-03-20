import crypto from "crypto";
import User from "../models/User.model.js";
import RefreshSession from "../models/RefreshSession.model.js";
import ApiError from "../utils/ApiError.js";
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

const hashToken = (token) =>
  crypto.createHash("sha256").update(String(token)).digest("hex");

const timingSafeEqual = (a, b) => {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
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
    const user = await User.create({ ...req.body, role: "user" });

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

    res.status(201).json({
      success: true,
      user,
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
