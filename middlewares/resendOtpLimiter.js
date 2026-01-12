import rateLimit from "express-rate-limit";

/**
 * Resend OTP Limiter
 * - Lebih ketat (anti spam)
 */
export const resendOtpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Please wait before requesting another OTP.",
  },
});

export default resendOtpLimiter;
