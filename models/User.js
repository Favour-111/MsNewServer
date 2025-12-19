// models/User.js (or wherever your schema is)
const mongoose = require("mongoose");

const orderSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    subtotal: { type: Number, required: true },
    serviceFee: { type: Number, required: true },
    university: { type: String, default: "Not provided" },
    Address: { type: String, required: true, default: "Not provided" },
    PhoneNumber: { type: String, default: "Not provided" },
    deliveryFee: { type: Number },
    currentStatus: { type: String, default: "Pending" },
    OrderOption: { type: String },
    rider: { type: String, default: "Not assigned" },
    packs: [
      {
        accepted: { type: Boolean, default: null },
        name: { type: String, required: true },
        vendorName: { type: String },
        vendorId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
        packType: { type: String, enum: ["small", "big", null], default: null },
        items: [
          {
            name: { type: String, required: true },
            price: { type: Number, required: true },
            quantity: { type: Number, required: true },
            image: { type: String },
            vendorName: { type: String },
            vendorId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
          },
        ],
      },
    ],

    deliveryNote: { type: String },
    vendorNote: { type: String },
    // 💬 NEW FIELD
    messages: [
      {
        text: { type: String, required: true },
        fromAdmin: { type: Boolean, default: true },
        createdAt: { type: Date, default: Date.now },
      },
    ],
  },
  { timestamps: true }
);

const paymentHistorySchema = new mongoose.Schema({
  orderId: { type: String },
  date: { type: Date, default: Date.now },
  price: { type: Number, required: true },
  type: { type: String, enum: ["in", "out"], required: true }, // "in" or "out"
  paystackAmount: { type: Number },
  paystackCharge: { type: Number },
  description: { type: String },
});

const userSchema = new mongoose.Schema(
  {
    fullName: { type: String, required: true },
    university: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: {
      type: String,
      enum: ["customer", "admin", "rider", "vendor"],
      default: "customer",
    },
    availableBal: { type: Number, default: 0 },
    orders: [{ type: mongoose.Schema.Types.ObjectId, ref: "Order" }],
    paymentHistory: [paymentHistorySchema],
    // Password reset fields
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date },
    // 💬 NEW FIELDS
    deliveryNote: { type: String },
    vendorNote: { type: String },
    messages: [
      {
        text: { type: String, required: true },
        fromAdmin: { type: Boolean, default: true },
        createdAt: { type: Date, default: Date.now },
      },
    ],
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
