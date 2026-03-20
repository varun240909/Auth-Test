import User from "../models/User.model.js";
import RefreshSession from "../models/RefreshSession.model.js";
import { verifyAccessToken } from "../utils/token.js";

export const protect = async (req, res, next) => {
  try {
    let token;
    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    }

    if (!token) {
      token = req.cookies?.accessToken;
    }

    if (!token) {
      return res.status(401).json({ message: "Not authorized" });
    }

    const decoded = verifyAccessToken(token);

    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    if (!user.isVerified) {
      return res.status(403).json({ message: "Account not verified" });
    }

    if (
      decoded?.tokenVersion === undefined ||
      decoded.tokenVersion !== user.tokenVersion
    ) {
      return res.status(401).json({ message: "Token revoked" });
    }

    if (!decoded?.sid) {
      return res.status(401).json({ message: "Invalid token session" });
    }

    const now = new Date();
    const activeSession = await RefreshSession.findOne({
      user: user._id,
      sessionId: decoded.sid,
      revokedAt: null,
      expiresAt: { $gt: now },
    }).select({ _id: 1 });

    if (!activeSession) {
      return res.status(401).json({ message: "Session expired" });
    }

    req.user = user;
    next();
  } catch (err) {
    next(err);
  }
};
