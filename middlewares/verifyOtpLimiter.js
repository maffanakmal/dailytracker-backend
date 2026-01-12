import rateLimit from "express-rate-limit";

/**
 * Verify OTP Limiter
 * - Cegah brute force OTP
 */
export const verifyOtpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 menit
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many OTP attempts. Please wait before trying again.",
  },
});

export default verifyOtpLimiter;
