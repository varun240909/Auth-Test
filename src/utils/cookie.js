const isProduction = process.env.NODE_ENV === "production";

const configuredSameSite = (process.env.COOKIE_SAMESITE || "").toLowerCase();
const sameSite =
  configuredSameSite === "lax" ||
  configuredSameSite === "strict" ||
  configuredSameSite === "none"
    ? configuredSameSite
    : isProduction
      ? "none"
      : "lax";

const secureConfigured = process.env.COOKIE_SECURE;
const secure =
  secureConfigured === "true"
    ? true
    : secureConfigured === "false"
      ? false
      : isProduction;

const effectiveSecure = sameSite === "none" ? true : secure;

export const accessCookieOptions = {
  httpOnly: true,
  secure: effectiveSecure,
  sameSite,
  path: "/api/users",
  maxAge: 15 * 60 * 1000, // 15 minutes
};

export const refreshCookieOptions = {
  httpOnly: true,
  secure: effectiveSecure,
  sameSite,
  path: "/api/users/refresh",
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
};

export const clearAccessCookieOptions = {
  path: accessCookieOptions.path,
  secure: accessCookieOptions.secure,
  sameSite: accessCookieOptions.sameSite,
};

export const clearRefreshCookieOptions = {
  path: refreshCookieOptions.path,
  secure: refreshCookieOptions.secure,
  sameSite: refreshCookieOptions.sameSite,
};
