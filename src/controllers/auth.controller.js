import bcrypt from "bcrypt";
import validator from "validator";
import supabaseClient from "../config/supabase.server.js";
import {
  generateAccessToken,
  generateRefreshToken,
  hashRefreshToken,
} from "../utils/token.js";

const DUMMY_HASH = "$2b$10$CwTycUXWue0Thq9StjUM0uJ8uK9O6qvYp8Z6K8FfH9gWbYyF7Z6aG";
const DEFAULT_ROLE = "User";

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
      .select("user_id, full_name, email, password, role, is_disabled")
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
        message: "Account is disabled",
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

    // Insert user
    const { data, error } = await supabaseClient
      .from("users")
      .insert({
        full_name,
        email,
        password: hashedPassword,
        role: DEFAULT_ROLE,
        is_active: true,
      })
      .select("user_id, full_name, email, created_at")
      .single();

    if (error) {
      console.error("REGISTER INSERT ERROR:", error);
      return res.status(500).json({
        success: false,
        message: "Failed to create account",
      });
    }

    return res.status(201).json({
      success: true,
      message: "Account created successfully",
      data,
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






