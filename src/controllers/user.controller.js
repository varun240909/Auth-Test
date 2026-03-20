import jwt from "jsonwebtoken";
import User from "../models/User.model.js";
import ApiError from "../utils/ApiError.js";
import { generateAccessToken, generateRefreshToken } from "../utils/token.js";
import { refreshCookieOptions } from "../utils/cookie.js";

export const register = async (req, res, next) => {
  try {
    const user = await User.create(req.body);

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    res.cookie("refreshToken", refreshToken, refreshCookieOptions);

    res.status(201).json({
      success: true,
      accessToken,
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

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    res.cookie("refreshToken", refreshToken, refreshCookieOptions);

    res.json({
      success: true,
      accessToken,
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

    const refreshSecret = process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET;
    if (!refreshSecret) {
      throw new ApiError(500, "JWT refresh secret not configured");
    }

    const decoded = jwt.verify(token, refreshSecret);

    const user = await User.findById(decoded.id);

    if (!user) {
      throw new ApiError(401, "User not found");
    }

    if (user.tokenVersion !== decoded.tokenVersion) {
      throw new ApiError(403, "Token reuse detected");
    }

    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    res.cookie("refreshToken", newRefreshToken, refreshCookieOptions);

    res.json({
      success: true,
      accessToken: newAccessToken,
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

export const logout = async (req, res) => {
  res.clearCookie("refreshToken", { path: refreshCookieOptions.path });

  res.json({
    success: true,
    message: "Logged out",
  });
};
