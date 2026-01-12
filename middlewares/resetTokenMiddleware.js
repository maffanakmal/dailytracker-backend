import jwt from "jsonwebtoken";

export default function resetTokenMiddleware(req, res, next) {
  const resetToken =
    req.body.resetToken ||
    req.headers["x-reset-token"];

  if (!resetToken) {
    return res.status(401).json({
      success: false,
      message: "Reset token is required",
    });
  }

  try {
    const decoded = jwt.verify(
      resetToken,
      process.env.JWT_SECRET
    );

    // Inject ke request
    req.resetUser = {
      userId: decoded.userId,
      email: decoded.email,
    };

    next();
  } catch (err) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired reset token",
    });
  }
}
