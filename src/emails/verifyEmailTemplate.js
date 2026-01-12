export const verifyEmailTemplate = ({ fullName, verifyUrl }) => {
  const subject = "Verify your email address";

  const text = `
Hi ${fullName},

Thank you for registering.

Please verify your email address by clicking the link below:

${verifyUrl}

If you did not create an account, please ignore this email.

Best regards,
APX Applicant Tracker Team
`;

  const html = `
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <title>Email Verification</title>
  </head>
  <body style="margin:0; padding:0; font-family:Poppins, sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td align="center" style="padding:40px 0;">
          <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff; border-radius:8px; overflow:hidden; border: 1px solid #d0d7de;">
            
            <!-- Header -->
            <tr>
              <td style="padding:20px; text-align:center;">
                <h1 style="color:#333333; margin:0; font-size:22px;">
                  APX Daily Tracker
                </h1>
              </td>
            </tr>

            <!-- Body -->
            <tr>
              <td style="padding:30px; color:#333333;">
                <p style="font-size:16px;">Hi <strong>${fullName}</strong>,</p>

                <p style="font-size:14px; line-height:1.6;">
                  Thank you for registering. Please verify your email address by clicking the button below.
                </p>

                <div style="text-align:center; margin:30px 0;">
                  <a href="${verifyUrl}"
                     style="
                       background:#0d6efd;
                       color:#ffffff;
                       padding:12px 24px;
                       text-decoration:none;
                       border-radius:6px;
                       font-size:14px;
                       display:inline-block;
                     ">
                    Verify Email
                  </a>
                </div>

                <p style="font-size:13px; color:#666;">
                  If the button doesn’t work, copy and paste this link into your browser:
                </p>

                <p style="font-size:12px; word-break:break-all; color:#0d6efd;">
                  ${verifyUrl}
                </p>

                <p style="font-size:13px; color:#666; margin-top:30px;">
                  If you did not create an account, you can safely ignore this email.
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

export default verifyEmailTemplate;