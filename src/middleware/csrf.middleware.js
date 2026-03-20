import crypto from "crypto";

const cookieName = process.env.CSRF_COOKIE_NAME || "csrfToken";
const headerName = "x-csrf-token";

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

const baseCookieOptions = {
  httpOnly: false,
  secure: effectiveSecure,
  sameSite,
  path: "/",
};

const createToken = () => crypto.randomBytes(32).toString("hex");

export const setCsrfCookie = (req, res) => {
  const existing = req.cookies?.[cookieName];
  const token = existing || createToken();

  res.cookie(cookieName, token, baseCookieOptions);
  return token;
};

export const requireCsrf = (req, res, next) => {
  const cookieToken = req.cookies?.[cookieName];
  const headerToken = req.get(headerName);

  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({
      success: false,
      message: "CSRF validation failed",
    });
  }

  next();
};
