// OK

import jwt from "jsonwebtoken";

export default function authMiddleware(req, res, next) {
  const token = req.cookies?.access_token;

  if (!token) {
    return res.status(401).json({
      success: false,
      code: "NO_TOKEN",
      message: "Authentication required",
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      issuer: "daily-tracker",
      audience: "authenticated-users",
    });

    req.user = decoded;
    next();
  } catch (err) {
    console.error("JWT ERROR:", err.name);

    if (err.name === "TokenExpiredError") {
      return res.status(401).json({
        success: false,
        code: "TOKEN_EXPIRED",
        message: "Access token expired",
      });
    }

    return res.status(401).json({
      success: false,
      code: "TOKEN_INVALID",
      message: "Invalid access token",
    });
  }
}