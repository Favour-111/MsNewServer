const mongoose = require("mongoose");
const vendorSchema = new mongoose.Schema(
  {
    storeName: { type: String, required: true },
    university: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    image: { type: String, required: false },
    Active: { type: String, default: false },
    role: {
      type: String,
      enum: ["customer", "admin", "rider", "vendor"],
      default: "vendor",
    },
    availableBal: { type: Number, default: 0 },
    fcmToken: { type: String }, // For push notifications
  },
  { timestamps: true }
);
module.exports = mongoose.model("vendors", vendorSchema);
