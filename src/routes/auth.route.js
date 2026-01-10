// OK

import express from "express";
import {
  login,
  refresh,
  register,
  logout,
} from "../controllers/auth.controller.js";

import authMiddleware from "../../middlewares/auth.middleware.js";
import loginRateLimiter from "../../middlewares/loginRateLimit.js";
import refreshRateLimiter from "../../middlewares/refreshRateLimit.js";
import registerRateLimiter from "../../middlewares/registerRateLimit.js";
import registerSlowDown from "../../middlewares/registerSlowDown.js"

import supabaseClient from "../config/supabase.server.js";

const router = express.Router();

// Public
router.post("/login", loginRateLimiter, login);
router.post("/register", registerRateLimiter, registerSlowDown, register);
router.post("/refresh", refreshRateLimiter, refresh);

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
