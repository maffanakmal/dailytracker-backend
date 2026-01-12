// OK

import express from "express";
import {
  login,
  refresh,
  register,
  verifyEmail,
  resendVerification,
  forgotPassword,
  verifyOtp,
  resendOtp,
  resetPassword,
  logout,
} from "../controllers/auth.controller.js";

import authMiddleware from "../../middlewares/auth.middleware.js";
import loginRateLimiter from "../../middlewares/loginRateLimit.js";
import refreshRateLimiter from "../../middlewares/refreshRateLimit.js";
import registerRateLimiter from "../../middlewares/registerRateLimit.js";
import registerSlowDown from "../../middlewares/registerSlowDown.js"
import resendVerificationLimiter from "../../middlewares/resendVerificationLimiter.js";
import forgotPasswordLimiter from "../../middlewares/forgotPasswordLimiter.js";
import verifyOtpLimiter from "../../middlewares/verifyOtpLimiter.js";
import resendOtpLimiter from "../../middlewares/resendOtpLimiter.js";
import resetTokenMiddleware from "../../middlewares/resetTokenMiddleware.js";

import supabaseClient from "../config/supabase.server.js";

const router = express.Router();

// Public
router.post("/login", loginRateLimiter, login);
router.post("/register", registerRateLimiter, registerSlowDown, register);
router.post("/verify-email", verifyEmail);
router.post("/resend-verification", resendVerificationLimiter, resendVerification);
router.post("/refresh", refreshRateLimiter, refresh);
router.post("/forgot-password", forgotPasswordLimiter, forgotPassword);
router.post("/verify-otp", verifyOtpLimiter, verifyOtp);
router.post("/resend-otp", resendOtpLimiter, resendOtp);
router.post("/reset-password", resetTokenMiddleware, resetPassword);

// Protected
router.post("/logout", authMiddleware, logout);

router.get("/profile", authMiddleware, async (req, res) => {
  const { data: user } = await supabaseClient
    .from("users")
    .select("full_name, email, role")
    .eq("user_id", req.user.user_id)
    .single();

  res.json({
    success: true,
    user,
  });
});

export default router;
