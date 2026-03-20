const isProduction = process.env.NODE_ENV === "production";

export const refreshCookieOptions = {
  httpOnly: true,
  secure: isProduction,
  sameSite: isProduction ? "strict" : "lax",
  path: "/api/users/refresh",
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
};
