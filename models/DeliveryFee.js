const mongoose = require("mongoose");

const deliveryFeeSchema = new mongoose.Schema(
  {
    vendorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "vendors",
      required: true,
      unique: true, // Each vendor can only have one delivery fee setup
    },
    minimumDeliveryFee: {
      type: Number,
      required: true,
    },
    maximumDeliveryFee: {
      type: Number,
      required: true,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("DeliveryFee", deliveryFeeSchema);
