import jwt from "jsonwebtoken";

export const generateAccessToken = (user) => {
  const accessSecret = process.env.JWT_ACCESS_SECRET || process.env.JWT_SECRET;
  if (!accessSecret) {
    throw new Error("JWT access secret not configured");
  }

  return jwt.sign({ id: user._id }, accessSecret, {
    expiresIn: "15m",
  });
};

export const generateRefreshToken = (user) => {
  const refreshSecret = process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET;
  if (!refreshSecret) {
    throw new Error("JWT refresh secret not configured");
  }

  return jwt.sign(
    {
      id: user._id,
      tokenVersion: user.tokenVersion,
    },
    refreshSecret,
    { expiresIn: "7d" },
  );
};
