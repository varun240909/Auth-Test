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

const parseExpiresInToMs = (value, fallbackMs) => {
  const raw = String(value || "").trim();
  if (!raw) return fallbackMs;

  if (/^\d+(\.\d+)?$/.test(raw)) {
    const seconds = Number(raw);
    if (!Number.isFinite(seconds) || seconds < 0) return fallbackMs;
    return Math.round(seconds * 1000);
  }

  const match = raw.match(/^(\d+(?:\.\d+)?)(ms|s|m|h|d|w|y)$/i);
  if (!match) return fallbackMs;

  const amount = Number(match[1]);
  if (!Number.isFinite(amount) || amount < 0) return fallbackMs;

  const unit = match[2].toLowerCase();
  const unitMs =
    unit === "ms"
      ? 1
      : unit === "s"
        ? 1000
        : unit === "m"
          ? 60 * 1000
          : unit === "h"
            ? 60 * 60 * 1000
            : unit === "d"
              ? 24 * 60 * 60 * 1000
              : unit === "w"
                ? 7 * 24 * 60 * 60 * 1000
                : 365 * 24 * 60 * 60 * 1000;

  return Math.round(amount * unitMs);
};

const accessMaxAge = parseExpiresInToMs(
  process.env.JWT_ACCESS_EXPIRES_IN || "15m",
  15 * 60 * 1000,
);

const refreshMaxAge = parseExpiresInToMs(
  process.env.JWT_REFRESH_EXPIRES_IN || "7d",
  7 * 24 * 60 * 60 * 1000,
);

export const accessCookieOptions = {
  httpOnly: true,
  secure: effectiveSecure,
  sameSite,
  path: "/api/users",
  maxAge: accessMaxAge,
};

export const refreshCookieOptions = {
  httpOnly: true,
  secure: effectiveSecure,
  sameSite,
  path: "/api/users/refresh",
  maxAge: refreshMaxAge,
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
