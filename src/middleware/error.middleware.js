export const errorHandler = (err, req, res, next) => {
  const isProduction = process.env.NODE_ENV === "production";
  if (isProduction) {
    console.error(err?.message || err);
  } else {
    console.error(err);
  }

  if (err?.message === "Not allowed by CORS") {
    return res.status(403).json({ success: false, message: err.message });
  }

  if (err?.name === "MongoServerError" && err?.code === 11000) {
    const field = Object.keys(err.keyValue || {})[0] || "field";
    return res.status(409).json({
      success: false,
      message: `${field} already exists`,
    });
  }

  if (err?.name === "TokenExpiredError" || err?.name === "JsonWebTokenError") {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired token",
    });
  }

  const statusCode = err.statusCode || 500;
  const message =
    statusCode >= 500 && isProduction
      ? "Internal Server Error"
      : err.message || "Internal Server Error";

  res.status(statusCode).json({
    success: false,
    message,
  });
};
