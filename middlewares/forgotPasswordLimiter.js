import rateLimit from "express-rate-limit";

/**
 * Forgot Password Limiter
 * - Cegah spam email
 */
export const forgotPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 menit
  max: 5, // max 5 request
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many password reset requests. Please try again later.",
  },
});

export default forgotPasswordLimiter;