const mongoose = require("mongoose");
const vendorSchema = new mongoose.Schema(
  {
    storeName: { type: String, required: true },
    university: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    image: { type: String, required: false },
    Active: { type: String, default: false },
    valid: { type: Boolean, default: null }, // null: not reviewed, false: rejected, true: approved
    role: {
      type: String,
      enum: ["customer", "admin", "rider", "vendor"],
      default: "vendor",
    },
    availableBal: { type: Number, default: 0 },
    fcmToken: { type: String }, // For push notifications
    // Bank account info for withdrawals
    bankAccountNumber: { type: String },
    bankAccountName: { type: String },
    bankName: { type: String },
    // ✅ AUDIT TRAIL: Track all financial transactions for security & fraud detection
    paymentHistory: [
      {
        orderId: { type: String, required: true },
        amount: { type: Number, required: true },
        type: { type: String, enum: ["in", "out"], required: true },
        date: { type: Date, default: Date.now },
        description: { type: String },
        previousBalance: { type: Number }, // Balance before transaction
        newBalance: { type: Number }, // Balance after transaction
      },
    ],
    // Password reset fields
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date },
  },
  { timestamps: true }
);
module.exports = mongoose.model("vendors", vendorSchema);
