// OK

import rateLimit from "express-rate-limit";

const registerRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 menit
  max: 5, // max 5 register
  standardHeaders: true,
  legacyHeaders: false,

  message: {
    success: false,
    message:
      "Too many registration attempts. Please try again later.",
  },
});

export default registerRateLimiter;
