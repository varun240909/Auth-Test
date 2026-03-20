import jwt from "jsonwebtoken";
import crypto from "crypto";

const parseList = (value) =>
  String(value || "")
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);

const getIssuer = () => (process.env.JWT_ISSUER || "").trim() || undefined;

const getAudience = () => {
  const audiences = parseList(process.env.JWT_AUDIENCE);
  if (audiences.length === 0) return undefined;
  return audiences.length === 1 ? audiences[0] : audiences;
};

const getAccessSecrets = () => {
  const secrets = parseList(process.env.JWT_ACCESS_SECRETS);
  if (secrets.length > 0) return secrets;
  const fallback = process.env.JWT_ACCESS_SECRET || process.env.JWT_SECRET;
  return fallback ? [fallback] : [];
};

const getRefreshSecrets = () => {
  const secrets = parseList(process.env.JWT_REFRESH_SECRETS);
  if (secrets.length > 0) return secrets;
  const fallback = process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET;
  return fallback ? [fallback] : [];
};

const getCommonVerifyOptions = () => ({
  algorithms: ["HS256"],
  issuer: getIssuer(),
  audience: getAudience(),
});

const signWithPrimarySecret = (secrets, payload, options) => {
  if (!secrets || secrets.length === 0) {
    throw new Error("JWT secret not configured");
  }
  return jwt.sign(payload, secrets[0], options);
};

const verifyWithAnySecret = (token, secrets, options) => {
  if (!secrets || secrets.length === 0) {
    throw new Error("JWT secret not configured");
  }

  let lastError;
  for (const secret of secrets) {
    try {
      return jwt.verify(token, secret, options);
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError;
};

const newJti = () =>
  typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : crypto.randomBytes(16).toString("hex");

export const generateAccessToken = (user, { sessionId } = {}) => {
  const secrets = getAccessSecrets();
  const issuer = getIssuer();
  const audience = getAudience();

  return signWithPrimarySecret(secrets, {
    id: user._id,
    tokenVersion: user.tokenVersion,
    ...(sessionId ? { sid: sessionId } : {}),
  }, {
    expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || "15m",
    issuer,
    audience,
    jwtid: newJti(),
  });
};

export const generateRefreshToken = (user, sessionId) => {
  const secrets = getRefreshSecrets();
  const issuer = getIssuer();
  const audience = getAudience();

  if (!sessionId) throw new Error("sessionId is required for refresh tokens");

  return signWithPrimarySecret(
    secrets,
    {
      id: user._id,
      tokenVersion: user.tokenVersion,
      sid: sessionId,
    },
    {
      expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || "7d",
      issuer,
      audience,
      jwtid: newJti(),
    },
  );
};

export const verifyAccessToken = (token) =>
  verifyWithAnySecret(token, getAccessSecrets(), getCommonVerifyOptions());

export const verifyRefreshToken = (token) =>
  verifyWithAnySecret(token, getRefreshSecrets(), getCommonVerifyOptions());
