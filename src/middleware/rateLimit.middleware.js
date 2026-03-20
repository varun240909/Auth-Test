const DEFAULT_MESSAGE = "Too many requests, please try again later";

const getKey = (req) => req.ip || "unknown";

const nowMs = () => Date.now();

const isMongoConnected = async () => {
  try {
    const mongoose = (await import("mongoose")).default;
    return mongoose?.connection?.readyState === 1;
  } catch {
    return false;
  }
};

const getMongoCollection = async () => {
  const mongoose = (await import("mongoose")).default;
  return mongoose.connection.db.collection("rate_limits");
};

export const createRateLimiter = ({
  windowMs,
  max,
  message = DEFAULT_MESSAGE,
  keyGenerator,
} = {}) => {
  if (!Number.isFinite(windowMs) || windowMs <= 0) {
    throw new Error("createRateLimiter: windowMs must be a positive number");
  }
  if (!Number.isFinite(max) || max <= 0) {
    throw new Error("createRateLimiter: max must be a positive number");
  }

  const storePreference = (process.env.RATE_LIMIT_STORE || "").toLowerCase();
  const shouldUseMongoByDefault = process.env.NODE_ENV === "production";
  const preferMongo =
    storePreference === "mongo" ||
    (storePreference === "" && shouldUseMongoByDefault);

  const hits = new Map();

  const cleanup = () => {
    const now = nowMs();
    for (const [key, entry] of hits.entries()) {
      if (entry.resetAt <= now) hits.delete(key);
    }
  };

  const cleanupInterval = setInterval(cleanup, Math.min(windowMs, 60 * 1000));
  cleanupInterval.unref?.();

  let indexesEnsured = false;

  const ensureIndexes = async (collection) => {
    if (indexesEnsured) return;
    try {
      await collection.createIndex({ key: 1 }, { unique: true });
      await collection.createIndex({ resetAt: 1 }, { expireAfterSeconds: 0 });
    } finally {
      indexesEnsured = true;
    }
  };

  const handleWithMemoryStore = (req, res, next) => {
    const key = (keyGenerator ? keyGenerator(req) : getKey(req)) || "unknown";
    const now = nowMs();

    let entry = hits.get(key);
    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + windowMs };
    }

    entry.count += 1;
    hits.set(key, entry);

    res.setHeader("X-RateLimit-Limit", String(max));
    res.setHeader(
      "X-RateLimit-Remaining",
      String(Math.max(0, max - entry.count)),
    );
    res.setHeader("X-RateLimit-Reset", String(Math.ceil(entry.resetAt / 1000)));

    if (entry.count > max) {
      return res.status(429).json({ success: false, message });
    }

    next();
  };

  const handleWithMongoStore = async (req, res, next) => {
    const key = (keyGenerator ? keyGenerator(req) : getKey(req)) || "unknown";

    const now = new Date();
    const resetAt = new Date(now.getTime() + windowMs);

    try {
      const collection = await getMongoCollection();
      await ensureIndexes(collection);

      const result = await collection.findOneAndUpdate(
        { key },
        [
          {
            $set: {
              key,
              resetAt: {
                $cond: [{ $gt: ["$resetAt", now] }, "$resetAt", resetAt],
              },
              count: {
                $cond: [
                  { $gt: ["$resetAt", now] },
                  { $add: [{ $ifNull: ["$count", 0] }, 1] },
                  1,
                ],
              },
            },
          },
        ],
        { upsert: true, returnDocument: "after" },
      );

      const doc = result?.value;
      const count = doc?.count ?? 1;
      const docResetAt = doc?.resetAt instanceof Date ? doc.resetAt : resetAt;

      res.setHeader("X-RateLimit-Limit", String(max));
      res.setHeader("X-RateLimit-Remaining", String(Math.max(0, max - count)));
      res.setHeader(
        "X-RateLimit-Reset",
        String(Math.ceil(docResetAt.getTime() / 1000)),
      );

      if (count > max) {
        return res.status(429).json({ success: false, message });
      }

      return next();
    } catch (err) {
      return next(err);
    }
  };

  return async (req, res, next) => {
    if (!preferMongo) return handleWithMemoryStore(req, res, next);

    const connected = await isMongoConnected();
    if (!connected) return handleWithMemoryStore(req, res, next);

    return handleWithMongoStore(req, res, next);
  };
};
