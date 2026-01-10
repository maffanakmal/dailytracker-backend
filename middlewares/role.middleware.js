// OK

export default function roleMiddleware(...allowedRoles) {
  const normalizedRoles = allowedRoles.map((r) => r.toLowerCase());

  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(401).json({
        success: false,
        code: "UNAUTHORIZED",
        message: "Authentication required",
      });
    }

    const userRole = req.user.role.toLowerCase();

    if (!normalizedRoles.includes(userRole)) {
      return res.status(403).json({
        success: false,
        code: "FORBIDDEN_ROLE",
        message: "You do not have permission to access this resource",
      });
    }

    next();
  };
}
