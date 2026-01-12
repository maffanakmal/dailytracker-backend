// OK

import rateLimit from "express-rate-limit";

const resendVerificationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 menit
  max: 5, // max 5 request per IP
  standardHeaders: true,
  legacyHeaders: false,

  message: {
    success: false,
    message: "Too many verification requests. Please try again later.",
  },

  handler: (req, res, next, options) => {
    res.status(429).json({
      success: false,
      message: "Please wait before resending verification email",
    });
  },
});

export default resendVerificationLimiter;

