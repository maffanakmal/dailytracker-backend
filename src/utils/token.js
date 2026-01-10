// OK

import jwt from "jsonwebtoken";
import crypto from "crypto";

const JWT_OPTIONS = {
  issuer: "daily-tracker",
  audience: "authenticated-users",
  algorithm: "HS256",
};

const getJwtSecret = () => {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET is not defined");
  }
  return process.env.JWT_SECRET;
};

export const generateAccessToken = (payload, expiresIn = "15m") => {
  return jwt.sign(
    {
      ...payload,
      jti: crypto.randomUUID(),
    },
    getJwtSecret(),
    {
      ...JWT_OPTIONS,
      expiresIn,
    }
  );
};

export const generateRefreshToken = () => {
  return crypto.randomBytes(64).toString("hex");
};

export const hashRefreshToken = (token) => {
  return crypto.createHash("sha256").update(token).digest("hex");
};

export const verifyAccessToken = (token) => {
  try {
    return jwt.verify(token, getJwtSecret(), JWT_OPTIONS);
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      throw new Error("TOKEN_EXPIRED");
    }
    if (err.name === "JsonWebTokenError") {
      throw new Error("TOKEN_INVALID");
    }
    throw err;
  }
};
