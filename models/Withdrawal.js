const mongoose = require("mongoose");

const withdrawalSchema = new mongoose.Schema(
  {
    vendorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "vendors",
      required: true,
    },
    vendorName: { type: String, required: true },
    amount: { type: Number, required: true },
    status: { type: Boolean, default: null }, // false = pending, true = processed
    date: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Withdrawal", withdrawalSchema);
