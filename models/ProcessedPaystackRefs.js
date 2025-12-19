const mongoose = require("mongoose");

const processedPaystackRefSchema = new mongoose.Schema({
  reference: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model(
  "ProcessedPaystackRefs",
  processedPaystackRefSchema
);
