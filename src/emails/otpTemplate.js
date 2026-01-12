export const otpTemplates = ({ fullName, otp, expiresIn = "5 minutes" }) => {
  const subject = "Your OTP Code";

  const text = `
Hi ${fullName},

You requested a password reset.

Use the OTP code below to continue:

${otp}

This OTP will expire in ${expiresIn}.

If you did not request this, please ignore this email.

Best regards,
APX Applicant Tracker Team
`;

  const html = `
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <title>OTP Verification</title>
  </head>
  <body style="margin:0; padding:0; font-family:Poppins, sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td align="center" style="padding:40px 0;">
          <table width="600" cellpadding="0" cellspacing="0"
            style="background:#ffffff; border-radius:8px; overflow:hidden; border:1px solid #d0d7de;">

            <!-- Header -->
            <tr>
              <td style="padding:20px; text-align:center;">
                <h1 style="color:#333; margin:0; font-size:22px;">
                  APX Applicant Tracker
                </h1>
              </td>
            </tr>

            <!-- Body -->
            <tr>
              <td style="padding:30px; color:#333;">
                <p style="font-size:16px;">
                  Hi <strong>${fullName}</strong>,
                </p>

                <p style="font-size:14px; line-height:1.6;">
                  You requested a password reset. Please use the OTP code below to continue:
                </p>

                <div style="
                  margin:30px auto;
                  text-align:center;
                  font-size:28px;
                  letter-spacing:6px;
                  font-weight:600;
                  color:#0d6efd;
                  background:#f1f5ff;
                  padding:16px;
                  border-radius:8px;
                ">
                  ${otp}
                </div>

                <p style="font-size:13px; color:#666; text-align:center;">
                  This OTP will expire in <strong>${expiresIn}</strong>.
                </p>

                <p style="font-size:13px; color:#666; margin-top:30px;">
                  If you did not request this action, you can safely ignore this email.
                </p>
              </td>
            </tr>

            <!-- Footer -->
            <tr>
              <td style="background:#f1f3f5; padding:15px; text-align:center; font-size:12px; color:#777;">
                © ${new Date().getFullYear()} APX Applicant Tracker
              </td>
            </tr>

          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
`;

  return { subject, html, text };
};

export default otpTemplates;
