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

module.exports = mongoose.model("Order", orderSchema);
