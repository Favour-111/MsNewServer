const mongoose = require("mongoose");

const managerSchema = new mongoose.Schema(
  {
    managerName: { type: String, required: true },
    university: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    Active: { type: String, default: "false" },
    role: {
      type: String,
      enum: ["customer", "admin", "rider", "vendor", "manager"],
      default: "manager",
    },
    availableBal: { type: Number, default: 0 },
  },
  { timestamps: true }
);

module.exports = mongoose.model("managers", managerSchema);
