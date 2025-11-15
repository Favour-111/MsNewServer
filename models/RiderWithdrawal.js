const mongoose = require("mongoose");

const riderWithdrawalSchema = new mongoose.Schema(
  {
    riderId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "riders", // replace with your Rider model name
      required: true,
    },
    riderName: { type: String, required: true },
    amount: { type: Number, required: true },
    status: { type: Boolean, default: null }, // null = pending, true = processed
    date: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

module.exports = mongoose.model("RiderWithdrawal", riderWithdrawalSchema);
