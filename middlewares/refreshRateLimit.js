// OK

import rateLimit from "express-rate-limit";

const refreshRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 menit
  max: 10, // max 10 refresh / menit
  standardHeaders: true,
  legacyHeaders: false,

  message: {
    success: false,
    message: "Too many refresh attempts, please slow down",
  },

  skipSuccessfulRequests: false, // tetap hitung
});

export default refreshRateLimiter;
