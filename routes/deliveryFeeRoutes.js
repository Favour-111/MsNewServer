const express = require("express");
const router = express.Router();
const DeliveryFee = require("../models/DeliveryFee");

// ✅ Add delivery fee
router.post("/add", async (req, res) => {
  try {
    const { vendorId, minimumDeliveryFee, maximumDeliveryFee } = req.body;

    // Prevent duplicates
    const existing = await DeliveryFee.findOne({ vendorId });
    if (existing) {
      return res
        .status(400)
        .json({ message: "Delivery fee already exists for this vendor" });
    }

    const fee = new DeliveryFee({
      vendorId,
      minimumDeliveryFee,
      maximumDeliveryFee,
    });
    await fee.save();

    res.status(201).json({ message: "Delivery fee added successfully", fee });
  } catch (error) {
    console.error("Error adding delivery fee:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ Get all delivery fees
router.get("/", async (req, res) => {
  try {
    // Use .lean() for faster query and only select needed fields
    const fees = await DeliveryFee.find()
      .populate("vendorId", "storeName email university")
      .lean();
    res.json(fees);
  } catch (error) {
    console.error("Error fetching delivery fees:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ Get delivery fee by vendor
router.get("/:vendorId", async (req, res) => {
  try {
    const fee = await DeliveryFee.findOne({ vendorId: req.params.vendorId });
    if (!fee)
      return res.status(404).json({ message: "Delivery fee not found" });
    res.json(fee);
  } catch (error) {
    console.error("Error fetching delivery fee:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ Update delivery fee
router.put("/:vendorId", async (req, res) => {
  try {
    const { minimumDeliveryFee, maximumDeliveryFee } = req.body;
    const updated = await DeliveryFee.findOneAndUpdate(
      { vendorId: req.params.vendorId },
      { minimumDeliveryFee, maximumDeliveryFee },
      { new: true }
    );
    if (!updated)
      return res.status(404).json({ message: "Delivery fee not found" });

    res.json({ message: "Delivery fee updated successfully", fee: updated });
  } catch (error) {
    console.error("Error updating delivery fee:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ Delete delivery fee
router.delete("/:vendorId", async (req, res) => {
  try {
    const deleted = await DeliveryFee.findOneAndDelete({
      vendorId: req.params.vendorId,
    });
    if (!deleted)
      return res.status(404).json({ message: "Delivery fee not found" });

    res.json({ message: "Delivery fee deleted successfully" });
  } catch (error) {
    console.error("Error deleting delivery fee:", error);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
