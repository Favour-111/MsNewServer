const express = require("express");
const router = express.Router();
const User = require("../models/User");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const emailService = require("../services/emailService");

// You should store processed references to prevent double-crediting
const ProcessedPaystackRefs = require("../models/ProcessedPaystackRefs");

// Helper to verify Paystack signature
function verifyPaystackSignature(req, secret) {
  const hash = crypto
    .createHmac("sha512", secret)
    .update(JSON.stringify(req.body))
    .digest("hex");
  return hash === req.headers["x-paystack-signature"];
}

router.post("/webhook/paystack", async (req, res) => {
  // Log every webhook event
  const logFile = path.join(__dirname, "../logs/paystack_webhook.log");
  const logEntry = `\n[${new Date().toISOString()}] Event: ${JSON.stringify(
    req.body
  )}`;
  try {
    fs.mkdirSync(path.dirname(logFile), { recursive: true });
    fs.appendFileSync(logFile, logEntry);
  } catch (logErr) {
    console.error("Failed to log webhook event:", logErr);
  }

  try {
    const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY;
    if (!verifyPaystackSignature(req, PAYSTACK_SECRET)) {
      return res.status(401).send("Invalid signature");
    }

    const event = req.body;
    if (event.event === "charge.success") {
      const reference = event.data.reference;
      // Always credit only the original intended amount (excluding Paystack charge)
      // Frontend should send the intended amount in metadata.amount
      let amount =
        event.data.metadata && event.data.metadata.amount
          ? Number(event.data.metadata.amount)
          : null;
      // If not present, try to infer from charged amount minus charge (if possible)
      if (!amount) {
        // Try to estimate charge (not 100% accurate if Paystack fee changes)
        let charged = event.data.amount / 100;
        let estCharge = Math.round(
          charged * 0.015 + (charged >= 2500 ? 100 : 0)
        );
        amount = charged - estCharge;
        // Fallback: if negative or zero, just use charged (should not happen)
        if (amount <= 0) amount = charged;
      }
      const email = event.data.customer.email;

      // Prevent double-crediting
      const alreadyProcessed = await ProcessedPaystackRefs.findOne({
        reference,
      });
      if (alreadyProcessed) return res.status(200).send("Already processed");

      // Find user by email (or use metadata for userId)
      const user = await User.findOne({ email });
      if (!user) return res.status(404).send("User not found");

      // Credit wallet with only the original deposit amount (not the total paid)
      user.availableBal = (user.availableBal || 0) + amount;
      user.paymentHistory = user.paymentHistory || [];
      user.paymentHistory.push({
        price: amount,
        type: "in",
        orderId: reference,
        date: new Date(),
      });
      await user.save();
      await ProcessedPaystackRefs.create({ reference, userId: user._id });
      return res.status(200).send("Wallet credited");
    }
    res.status(200).send("Ignored");
  } catch (error) {
    console.error("Paystack webhook error:", error);
    // Log error
    const errorLog = `\n[${new Date().toISOString()}] ERROR: ${
      error.stack || error
    }`;
    try {
      fs.appendFileSync(logFile, errorLog);
    } catch (logErr) {
      console.error("Failed to log webhook error:", logErr);
    }
    // Send alert email to admin
    try {
      await emailService.sendEmail({
        to: process.env.ADMIN_EMAIL || "admin@example.com",
        subject: "Paystack Webhook Processing Error",
        text: `Error: ${error.stack || error}\nEvent: ${JSON.stringify(
          req.body
        )}`,
      });
    } catch (emailErr) {
      console.error("Failed to send error alert email:", emailErr);
    }
    res.status(500).json({ error: "Webhook processing failed" });
  }
});

module.exports = router;
