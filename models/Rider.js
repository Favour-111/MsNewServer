const mongoose = require("mongoose");
const riderSchema = new mongoose.Schema(
  {
    userName: { type: String, required: true },
    university: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phoneNumber: { type: String, required: true },
    password: { type: String, required: true },
    role: {
      type: String,
      enum: ["customer", "admin", "rider", "vendor"],
      default: "rider",
    },
    availableBal: { type: Number, default: 0 },
    fcmToken: { type: String }, // For push notifications
    valid: { type: Boolean, default: null }, // null: not reviewed, false: rejected, true: approved
    // Password reset fields
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date },
  },
  { timestamps: true }
);
module.exports = mongoose.model("riders", riderSchema);
