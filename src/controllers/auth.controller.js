import bcrypt from "bcrypt";
import crypto from "crypto";
import validator from "validator";
import supabaseClient from "../config/supabase.server.js";
import {
  generateAccessToken,
  generateRefreshToken,
  hashRefreshToken,
} from "../utils/token.js";
import verifyEmailTemplate from "../emails/verifyEmailTemplate.js";
import otpTemplate from "../emails/otpTemplate.js";
import sendEmail from "../utils/sendEmail.js";

const DUMMY_HASH = "$2b$10$CwTycUXWue0Thq9StjUM0uJ8uK9O6qvYp8Z6K8FfH9gWbYyF7Z6aG";
const DEFAULT_ROLE = "User";
const DEFAULT_STATUS = "Pending";
const RESEND_LIMIT_SECONDS = 60;

const FRONTEND_URL = process.env.FRONTEND_URL;

// OK
export const login = async (req, res) => {
  try {
    let { email, password, rememberMe = false } = req.body;
    const errors = {};

    email = email?.trim().toLowerCase();

    if (!email) errors.email = ["Email is required"];
    else if (!validator.isEmail(email)) errors.email = ["Invalid email"];

    if (!password) errors.password = ["Password is required"];

    if (Object.keys(errors).length > 0) {
      return res.status(422).json({ success: false, errors });
    }

    const { data: user, error } = await supabaseClient
      .from("users")
      .select("user_id, full_name, email, password, role, status")
      .eq("email", email)
      .maybeSingle();

    if (error) {
      console.error("DB ERROR:", error);
      return res.status(500).json({
        success: false,
        message: "Database error",
      });
    }

    if (!user) {
      await bcrypt.compare(password, DUMMY_HASH);
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    if (user.is_disabled) {
      return res.status(403).json({
        success: false,
        message: "Your account is disabled",
      });
    }

    if (user.status !== "Active") {
      return res.status(403).json({
        success: false,
        message: "Please verify your email first",
      });
    }

    const isValid = await bcrypt.compare(password, user.password);

    if (!isValid) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    await supabaseClient
      .from("users")
      .update({ last_login_at: new Date().toISOString() })
      .eq("user_id", user.user_id);

    const accessToken = generateAccessToken(
      {
        user_id: user.user_id,
        email: user.email,
        role: user.role,
      },
      rememberMe ? "14d" : "15m"
    );

    const refreshToken = generateRefreshToken();
    const hashedRefreshToken = hashRefreshToken(refreshToken);

    const refreshExpiresAt = new Date(
      Date.now() +
        (rememberMe ? 30 : 7) * 24 * 60 * 60 * 1000
    );

    await supabaseClient
      .from("user_sessions")
      .update({ is_active: false })
      .eq("user_id", user.user_id)
      .eq("is_active", true);

    const { error: sessionError } = await supabaseClient
      .from("user_sessions")
      .insert({
        user_id: user.user_id,
        refresh_token: hashedRefreshToken,
        expires_at: refreshExpiresAt,
        is_active: true,
        remember_me: rememberMe,
        last_seen: new Date().toISOString(),
      });

    if (sessionError) {
      console.error("SESSION ERROR:", sessionError);
      return res.status(500).json({
        success: false,
        message: "Failed to create session",
      });
    }

    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
    };

    res.cookie("access_token", accessToken, {
      ...cookieOptions,
      maxAge: rememberMe
        ? 14 * 24 * 60 * 60 * 1000
        : 15 * 60 * 1000,
    });

    res.cookie("refresh_token", refreshToken, {
      ...cookieOptions,
      maxAge:
        (rememberMe ? 30 : 7) * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      success: true,
      message: "Login successful",
      user: {
        user_id: user.user_id,
        full_name: user.full_name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
}

// OK
export const refresh = async (req, res) => {
  try {
    const refreshToken = req.cookies?.refresh_token;
    if (!refreshToken) {
      return res.status(401).json({ message: "No refresh token" });
    }

    const hashedToken = hashRefreshToken(refreshToken);

    const { data: session, error } = await supabaseClient
      .from("user_sessions")
      .select("session_id, user_id, expires_at, remember_me")
      .eq("refresh_token", hashedToken)
      .eq("is_active", true)
      .gt("expires_at", new Date())
      .maybeSingle();

    // 🔐 Reuse detection
    if (error || !session) {
      await supabaseClient
        .from("user_sessions")
        .update({ is_active: false })
        .eq("refresh_token", hashedToken);

      return res.status(401).json({
        message: "Invalid refresh token",
      });
    }

    // Rotate refresh token
    const newRefreshToken = generateRefreshToken();
    const newHashedToken = hashRefreshToken(newRefreshToken);

    const refreshDays = session.remember_me ? 30 : 7;
    const newExpiresAt = new Date(
      Date.now() + refreshDays * 24 * 60 * 60 * 1000
    );

    await supabaseClient
      .from("user_sessions")
      .update({
        refresh_token: newHashedToken,
        expires_at: newExpiresAt,
        last_seen: new Date().toISOString(),
      })
      .eq("session_id", session.session_id);

    const accessToken = generateAccessToken(
      { user_id: session.user_id },
      "15m"
    );

    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
    };

    res.cookie("access_token", accessToken, {
      ...cookieOptions,
      maxAge: 15 * 60 * 1000,
    });

    res.cookie("refresh_token", newRefreshToken, {
      ...cookieOptions,
      maxAge: refreshDays * 24 * 60 * 60 * 1000,
    });

    return res.json({ success: true });
  } catch (err) {
    console.error("REFRESH ERROR:", err);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
};

// OK
export const register = async (req, res) => {
  try {
    let { full_name, email, password } = req.body;
    const errors = {};

    full_name = full_name?.trim();
    email = email?.trim().toLowerCase();

    // Validation
    if (!full_name || full_name.length < 3) {
      errors.full_name = ["Full name must be at least 3 characters"];
    }

    if (!email || !validator.isEmail(email)) {
      errors.email = ["Invalid email"];
    }

    if (!password || password.length < 8) {
      errors.password = ["Password must be at least 8 characters"];
    }

    if (Object.keys(errors).length > 0) {
      return res.status(422).json({ success: false, errors });
    }

    // Check existing user
    const { data: existingUser, error: checkError } = await supabaseClient
      .from("users")
      .select("user_id")
      .eq("email", email)
      .maybeSingle();

    if (checkError) {
      console.error("REGISTER CHECK ERROR:", checkError);
      return res.status(500).json({
        success: false,
        message: "Database error",
      });
    }

    if (existingUser) {
      return res.status(422).json({
        success: false,
        errors: {
          email: ["Email already exists"],
        },
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user (PENDING)
    const { data: user, error } = await supabaseClient
      .from("users")
      .insert({
        full_name,
        email,
        password: hashedPassword,
        role: DEFAULT_ROLE,
        status: DEFAULT_STATUS,
      })
      .select("user_id, full_name, email")
      .single();

    if (error) {
      console.error("REGISTER INSERT ERROR:", error);
      return res.status(500).json({
        success: false,
        message: "Failed to create account",
      });
    }

    // Email verif token
    const token = crypto.randomBytes(32).toString("hex");

    await supabaseClient.from("email_verifications").insert({
      user_id: user.user_id,
      token,
      expires_at: new Date(Date.now() + 15 * 60 * 1000), // 15 menit
    });

    const verifyUrl = `${FRONTEND_URL}/auth/verify-email?token=${token}`;

    const { subject, html, text } = verifyEmailTemplate({
      fullName: full_name,
      verifyUrl,
    });

    await sendEmail({
      to: email,
      subject,
      html,
      text,
    });

    return res.status(201).json({
      success: true,
      message: "Account created. Please check your email to verify.",
    });
  } catch (err) {
    console.error("REGISTER CATCH ERROR:", err);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// OK
export const verifyEmail = async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ message: "Invalid token" });
  }

  const { data: record } = await supabaseClient
    .from("email_verifications")
    .select("*")
    .eq("token", token)
    .maybeSingle();

  if (!record) {
    return res.status(400).json({ message: "Token invalid or expired" });
  }

  if (new Date(record.expires_at) < new Date()) {
    return res.status(400).json({ message: "Token expired" });
  }

  await supabaseClient
    .from("users")
    .update({
      status: "Active",
      verified_at: new Date(),
    })
    .eq("user_id", record.user_id);

  await supabaseClient
    .from("email_verifications")
    .delete()
    .eq("email_verification_id", record.email_verification_id);

  return res.json({
    success: true,
    message: "Email verified successfully",
  });
};

// OK
export const resendVerification = async (req, res) => {
  try {
    const { token: oldToken } = req.body;

    if (!oldToken) {
      return res.status(400).json({ message: "Token required" });
    }

    // 1. Cari token lama
    const { data: verification } = await supabaseClient
      .from("email_verifications")
      .select("user_id")
      .eq("token", oldToken)
      .single();

    if (!verification) {
      return res.status(400).json({
        success: false,
        message: "Invalid verification token",
      });
    }

    const userId = verification.user_id;

    // 2. Ambil user
    const { data: user } = await supabaseClient
      .from("users")
      .select("email, full_name, verified_at, last_verified_at")
      .eq("user_id", userId)
      .single();

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.verified_at) {
      return res.status(400).json({
        success: false,
        message: "Email already verified",
      });
    }

    // 3. Rate limit resend
    if (user.last_verified_at) {
      const diffSeconds =
        (Date.now() - new Date(user.last_verified_at)) / 1000;

      if (diffSeconds < RESEND_LIMIT_SECONDS) {
        return res.status(429).json({
          success: false,
          message: `Please wait ${Math.ceil(
            RESEND_LIMIT_SECONDS - diffSeconds
          )} seconds before resending`,
        });
      }
    }

    // 4. Hapus token lama
    await supabaseClient
      .from("email_verifications")
      .delete()
      .eq("user_id", userId);

    // 5. Buat token baru
    const newToken = crypto.randomBytes(32).toString("hex");

    await supabaseClient.from("email_verifications").insert({
      user_id: userId,
      token: newToken,
      expires_at: new Date(Date.now() + 60 * 60 * 1000), // 1 jam
    });

    await supabaseClient
      .from("users")
      .update({ last_verified_at: new Date() })
      .eq("user_id", userId);

    // 6. Kirim email
    const verifyUrl = `${FRONTEND_URL}/auth/verify-email?token=${newToken}`;

    const { subject, html, text } = verifyEmailTemplate({
      fullName: user.full_name,
      verifyUrl,
    });

    await sendEmail({
      to: user.email,
      subject,
      html,
      text,
    });

    return res.json({
      success: true,
      message: "Verification email sent",
    });
  } catch (err) {
    console.error("RESEND VERIFICATION ERROR:", err);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// OK
export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    // Find user (NO password select)
    const { data: user, error: userError } = await supabaseClient
      .from("users")
      .select("user_id, full_name, email, status, verified_at")
      .eq("email", email)
      .maybeSingle();

    // Prevent email enumeration
    if (userError) {
      return res.status(200).json({
        message: "If that email exists, an OTP has been sent",
      });
    }

    if (!user || !user.verified_at || user.status?.toLowerCase() !== "active") {
      return res.status(200).json({
        message: "If that email exists, an OTP has been sent",
      });
    }

    // check active, jika user belum verif email tidak bisa reset password
    // tombol di semua auth jika error tidak balik ke semula

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    const otpHash = crypto
      .createHash("sha256")
      .update(otp)
      .digest("hex");

    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    // Invalidate previous unused OTPs (IMPORTANT)
    await supabaseClient
      .from("reset_passwords")
      .update({ used: true })
      .eq("user_id", user.user_id)
      .eq("used", false);

    // Insert new OTP
    const { error: insertError } = await supabaseClient
      .from("reset_passwords")
      .insert({
        user_id: user.user_id,
        otp_hash: otpHash,
        expires_at: expiresAt,
        attempts: 0,
        used: false,
      });

    if (insertError) {
      console.error("OTP INSERT ERROR:", insertError);
      return res.status(500).json({ message: "Server error" });
    }

    const expiresIn = "5 Minutes";

    const { subject, html, text } = otpTemplate({
      fullName: user.full_name,
      otp,
      expiresIn,
    });

    await sendEmail({
      to: email,
      subject,
      html,
      text,
    });

    return res.status(200).json({
      message: "If that email exists, an OTP has been sent",
    });
  } catch (error) {
    console.error("FORGOT PASSWORD OTP ERROR:", error);
    return res.status(500).json({ message: "Server error" });
  }
};

// OK
export const verifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ message: "Email and OTP are required" });
    }

    const { data: user } = await supabaseClient
      .from("users")
      .select("user_id")
      .eq("email", email)
      .maybeSingle();

    if (!user) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    const otpHash = crypto
      .createHash("sha256")
      .update(otp)
      .digest("hex");

    const { data: resetOtp } = await supabaseClient
      .from("reset_passwords")
      .select("*")
      .eq("user_id", user.user_id)
      .eq("otp_hash", otpHash)
      .eq("used", false)
      .gt("expires_at", new Date().toISOString())
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (!resetOtp) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    // IMPORTANT PART
    await supabaseClient
      .from("reset_passwords")
      .update({
        verified: true,
        verified_at: new Date().toISOString(),
      })
      .eq("reset_password_id", resetOtp.reset_password_id);

    return res.status(200).json({
      message: "OTP verified",
    });
  } catch (err) {
    console.error("VERIFY OTP ERROR:", err);
    return res.status(500).json({ message: "Server error" });
  }
};

export const resendOtp = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    // 1. Cari user
    const { data: user } = await supabaseClient
      .from("users")
      .select("user_id, email, full_name, status")
      .eq("email", email)
      .maybeSingle();

    // Prevent email enumeration
    if (!user) {
      return res.status(200).json({
        message: "If that email exists, an OTP has been sent",
      });
    }

    if (user.status !== "Active") {
      return res.status(200).json({
        message: "If that email exists, an OTP has been sent",
      });
    }

    // 2. Rate limit resend (ambil OTP terakhir)
    const { data: lastOtp } = await supabaseClient
      .from("reset_passwords")
      .select("created_at")
      .eq("user_id", user.user_id)
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (lastOtp) {
      const diffSeconds =
        (Date.now() - new Date(lastOtp.created_at).getTime()) / 1000;

      if (diffSeconds < RESEND_LIMIT_SECONDS) {
        return res.status(429).json({
          message: `Please wait ${Math.ceil(
            RESEND_LIMIT_SECONDS - diffSeconds
          )} seconds before resending`,
        });
      }
    }

    // 3. Invalidate OTP lama
    await supabaseClient
      .from("reset_passwords")
      .update({ used: true })
      .eq("user_id", user.user_id)
      .eq("used", false);

    // 4. Generate OTP baru
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    const otpHash = crypto
      .createHash("sha256")
      .update(otp)
      .digest("hex");

    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 menit

    await supabaseClient.from("reset_passwords").insert({
      user_id: user.user_id,
      otp_hash: otpHash,
      expires_at: expiresAt,
      attempts: 0,
      used: false,
    });

    // 5. Kirim email OTP
    const expiresIn = "5 minutes";

    const { subject, html, text } = otpTemplate({
      fullName: user.full_name,
      otp,
      expiresIn,
    });

    await sendEmail({
      to: user.email,
      subject,
      html,
      text,
    });

    return res.status(200).json({
      message: "If that email exists, an OTP has been sent",
    });
  } catch (error) {
    console.error("RESEND OTP ERROR:", error);
    return res.status(500).json({ message: "Server error" });
  }
};

// OK
export const resetPassword = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required",
      });
    }

    // Get user
    const { data: user } = await supabaseClient
      .from("users")
      .select("user_id")
      .eq("email", email)
      .maybeSingle();

    if (!user) {
      return res.status(400).json({
        message: "Invalid reset request",
      });
    }

    // Get latest VERIFIED OTP
    const { data: resetOtp } = await supabaseClient
      .from("reset_passwords")
      .select("*")
      .eq("user_id", user.user_id)
      .eq("verified", true)
      .eq("used", false)
      .gt("expires_at", new Date().toISOString())
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (!resetOtp) {
      return res.status(400).json({
        message: "Reset session expired",
      });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update password
    await supabaseClient
      .from("users")
      .update({ password: hashedPassword })
      .eq("user_id", user.user_id);

    // Invalidate OTP
    await supabaseClient
      .from("reset_passwords")
      .update({ used: true })
      .eq("reset_password_id", resetOtp.reset_password_id);

    return res.status(200).json({
      message: "Password reset successful",
    });
  } catch (error) {
    console.error("RESET PASSWORD ERROR:", error);
    return res.status(500).json({ message: "Server error" });
  }
};

// OK
export const logout = async (req, res) => {
  try {
    const refreshToken = req.cookies?.refresh_token;

    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
    };

    if (!refreshToken) {
      res.clearCookie("access_token", cookieOptions);
      res.clearCookie("refresh_token", cookieOptions);

      return res.status(200).json({
        success: true,
        message: "Already logged out",
      });
    }

    const hashedRefreshToken = hashRefreshToken(refreshToken);

    await supabaseClient
      .from("user_sessions")
      .update({
        is_active: false,
        last_seen: new Date().toISOString(),
      })
      .eq("refresh_token", hashedRefreshToken)
      .eq("is_active", true);

    res.clearCookie("access_token", cookieOptions);
    res.clearCookie("refresh_token", cookieOptions);

    return res.status(200).json({
      success: true,
      message: "Logout successful",
    });
  } catch (err) {
    console.error("LOGOUT ERROR:", err);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// OK
export const logoutAll = async (req, res) => {
  try {
    const userId = req.user?.user_id;

    if (!userId) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized",
      });
    }

    await supabaseClient
      .from("user_sessions")
      .update({
        is_active: false,
        last_seen: new Date().toISOString(),
      })
      .eq("user_id", userId)
      .eq("is_active", true);

    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
    };

    res.clearCookie("access_token", cookieOptions);
    res.clearCookie("refresh_token", cookieOptions);

    return res.status(200).json({
      success: true,
      message: "Logged out from all devices",
    });
  } catch (err) {
    console.error("LOGOUT ALL ERROR:", err);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// Next : 1. saat user sudah active terus login dan ganti email, harus di verif email lagi. 2. Lupa password dan otp





