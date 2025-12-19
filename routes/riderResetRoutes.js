const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const Rider = require("../models/Rider");
const { sendEmailViaBrevoApi } = require("../services/emailService");
const router = express.Router();

// POST /api/riders/forgot-password
router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  try {
    const rider = await Rider.findOne({ email });
    if (!rider) return res.status(404).json({ message: "Rider not found" });
    const resetToken = crypto.randomBytes(32).toString("hex");
    const hashedToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");
    rider.resetPasswordToken = hashedToken;
    rider.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await rider.save();
    const resetLink = `${process.env.CLIENT_APP_URL}/reset-password/${resetToken}`;
    await sendEmailViaBrevoApi({
      to: rider.email,
      subject: "Reset Your Rider Password",
      html: `
        <div style="background: #fff7f2; min-height: 100vh; padding: 0; margin: 0; font-family: 'Segoe UI', Arial, sans-serif;">
          <div style="max-width: 440px; margin: 56px auto 32px auto; background: #fff; border-radius: 24px; box-shadow: 0 6px 32px rgba(201,26,26,0.10); border: 1.5px solid #f3e5e5; padding: 44px 32px 36px 32px;">
            <div style="display: flex; flex-direction: column; justify-content: center; align-items: center;">
              <img src="https://github.com/Favour-111/my-asset/blob/main/images%20(2).jpeg?raw=true" alt="MealSection Logo" style="width: 150px; " />
              </div>
              <p style="text-align: center; color: #b71c1c; font-size: 13px; font-weight: 500; margin-bottom: 10px;">Food Delivery for Universities</p>
            <h2 style="font-size: 1.22rem;  font-weight: 700; margin-bottom: 12px; text-align: center;">Hi ${
              rider.userName
            } 👋</h2>
            <p style="color: #787878; font-size: 13px; margin-bottom: 24px; text-align: center;">We received a request to reset your rider account password. Click the button below to set a new password. If you did not request this, you can safely ignore this email.</p>
            <div style="text-align: center; margin-bottom: 24px;">
              <a href="${resetLink}" style="display: inline-block; background: linear-gradient(90deg, #9e0505 0%, #c91a1a 100%); color: #fff; font-weight: 500; padding: 16px 40px; border-radius: 14px; text-decoration: none; font-size: 13px; box-shadow: 0 2px 12px rgba(201,26,26,0.13); transition: background 0.2s, transform 0.2s;">Reset Password</a>
            </div>
            <p style="color: #888; font-size: 0.99rem; margin-top: 0; text-align: center;">This link will expire in 1 hour for your security.</p>
            <hr style="border: none; border-top: 1.5px solid #f3e5e5; margin: 28px 0 16px 0;" />
            <p style="color: #b71c1c; font-size: 0.99rem; margin: 0; text-align: center;">Questions? <a href="mailto:mealsection@gmail.com" style="color: #c91a1a; text-decoration: underline;">mealsection@gmail.com</a></p>
            <a href="https://favour-111.github.io/my-portfolio/" target="_blank" rel="noopener" style="color: #bbb; font-size: 0.89rem; margin-top: 16px; text-align: center; text-decoration: underline;">&copy; ${new Date().getFullYear()} Horbah's Tech. All rights reserved.</a>
          </div>
        </div>
      `,
    });
    res.json({ message: "Password reset link sent to your email" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// POST /api/riders/reset-password/:token
router.post("/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;
  if (!newPassword)
    return res.status(400).json({ message: "New password is required" });
  try {
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
    const rider = await Rider.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() },
    });
    if (!rider)
      return res.status(400).json({ message: "Invalid or expired token" });
    rider.password = await bcrypt.hash(newPassword, 10);
    rider.resetPasswordToken = undefined;
    rider.resetPasswordExpires = undefined;
    await rider.save();
    res.json({ message: "Password reset successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
