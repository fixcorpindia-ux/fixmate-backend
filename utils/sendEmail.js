import nodemailer from "nodemailer";

export async function sendEmail(to, subject, text) {
  try {
    let transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS 
      }
    });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to,
      subject,
      text
    });

    console.log("📩 Email sent to:", to);
  } catch (err) {
    console.error("❌ Email send error:", err.message);
  }
}
