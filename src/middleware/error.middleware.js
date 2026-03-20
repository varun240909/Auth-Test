export const errorHandler = (err, req, res, next) => {
  console.error(err);

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

  res.status(err.statusCode || 500).json({
    success: false,
    message: err.message || "Internal Server Error",
  });
};
