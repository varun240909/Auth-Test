import User from "../models/User.model.js";
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

    if (
      decoded?.tokenVersion === undefined ||
      decoded.tokenVersion !== user.tokenVersion
    ) {
      return res.status(401).json({ message: "Token revoked" });
    }

    req.user = user;
    next();
  } catch (err) {
    next(err);
  }
};
