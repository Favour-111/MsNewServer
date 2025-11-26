const mongoose = require("mongoose");

const packPriceSchema = new mongoose.Schema(
  {
    vendorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "vendors",
      required: true,
      unique: true,
    },
    smallPackPrice: {
      type: Number,
      required: true,
    },
    bigPackPrice: {
      type: Number,
      required: true,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("PackPrice", packPriceSchema);
