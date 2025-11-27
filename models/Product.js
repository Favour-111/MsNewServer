const mongoose = require("mongoose");

const productSchema = new mongoose.Schema(
  {
    vendorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "vendors", // Reference your vendor model
      required: true,
    },
    title: { type: String, required: true },
    price: { type: Number },
    category: {
      type: String,
      enum: ["Carbohydrate", "Protein", "Drinks", "Pastries", "Packs"],
      required: true,
    },

    image: { type: String },
    available: { type: Boolean, default: true },
    packs: {
      small: {
        price: { type: Number },
        available: { type: Boolean, default: true },
      },
      big: {
        price: { type: Number },
        available: { type: Boolean, default: true },
      },
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("products", productSchema);
