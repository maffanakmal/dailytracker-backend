// OK

import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: process.env.SMTP_SECURE === "true",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

/**
 * Optional: verify SMTP connection on startup
 * (recommended in development)
 */
if (process.env.NODE_ENV !== "production") {
  transporter.verify((error) => {
    if (error) {
      console.error("SMTP CONFIG ERROR:", error);
    } else {
      console.log("SMTP server ready");
    }
  });
}

export default transporter;
