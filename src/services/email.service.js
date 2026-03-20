import nodemailer from "nodemailer";

const isProduction = process.env.NODE_ENV === "production";

const provider = (process.env.EMAIL_PROVIDER || "gmail").trim().toLowerCase();
const gmailUser = (process.env.GMAIL_USER || "").trim();
const gmailAppPassword = (process.env.GMAIL_APP_PASSWORD || "").trim();

const fromAddress =
  (process.env.EMAIL_FROM || "").trim() ||
  (gmailUser ? `No Reply <${gmailUser}>` : "");

let cachedTransporter;

export const isEmailConfigured = () => {
  if (provider !== "gmail") return false;
  return Boolean(gmailUser && gmailAppPassword && fromAddress);
};

const getTransporter = () => {
  if (cachedTransporter) return cachedTransporter;

  if (!isEmailConfigured()) {
    throw new Error("Email provider not configured");
  }

  cachedTransporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: gmailUser,
      pass: gmailAppPassword,
    },
  });

  return cachedTransporter;
};

export const sendEmail = async ({ to, subject, text, html }) => {
  const transporter = getTransporter();

  const info = await transporter.sendMail({
    from: fromAddress,
    to,
    subject,
    text,
    html,
  });

  if (!isProduction) {
    console.log("Email sent:", {
      messageId: info?.messageId,
      accepted: info?.accepted,
      rejected: info?.rejected,
    });
  }

  return info;
};

const getApiBaseUrl = () => (process.env.API_BASE_URL || "").trim();

export const buildVerifyEmailLink = ({ email, token }) => {
  const base = getApiBaseUrl();
  if (!base) {
    throw new Error("API_BASE_URL is required to build verification links");
  }
  const url = new URL("/api/users/verify-email", base);
  url.searchParams.set("email", email);
  url.searchParams.set("token", token);
  return url.toString();
};

export const sendVerificationEmail = async ({ to, token }) => {
  const link = buildVerifyEmailLink({ email: to, token });

  const subject = "Verify your email";
  const text = `Verify your email by opening this link:\n\n${link}\n\nIf you didn't create this account, you can ignore this email.`;
  const html = `
    <p>Verify your email by clicking this link:</p>
    <p><a href="${link}">Verify email</a></p>
    <p>If you didn't create this account, you can ignore this email.</p>
  `.trim();

  return sendEmail({ to, subject, text, html });
};
