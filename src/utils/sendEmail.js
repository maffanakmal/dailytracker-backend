import transporter from "../config/mailer.js";

const sendEmail = async ({ to, subject, html, text }) => {
  try {
    await transporter.sendMail({
      from: `"${process.env.MAIL_FROM_NAME}" <${process.env.MAIL_FROM_ADDRESS}>`,
      to,
      subject,
      html,
      text,
    });
  } catch (error) {
    console.error("SEND EMAIL ERROR:", error);
    throw new Error("Failed to send email");
  }
};

export default sendEmail;
