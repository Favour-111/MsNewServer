const express = require("express");
const router = express.Router();
const PackPrice = require("../models/PackPrice");

// Create or update pack prices for a vendor
router.post("/", async (req, res) => {
  const { vendorId, smallPackPrice, bigPackPrice } = req.body;
  if (!vendorId || smallPackPrice == null || bigPackPrice == null) {
    return res.status(400).json({ error: "Missing required fields." });
  }
  try {
    let packPrice = await PackPrice.findOne({ vendorId });
    if (packPrice) {
      packPrice.smallPackPrice = smallPackPrice;
      packPrice.bigPackPrice = bigPackPrice;
      await packPrice.save();
    } else {
      packPrice = await PackPrice.create({
        vendorId,
        smallPackPrice,
        bigPackPrice,
      });
    }
    res.json(packPrice);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get pack prices for a vendor
router.get("/:vendorId", async (req, res) => {
  try {
    // Use .lean() for faster query and only select needed fields
    const packPrice = await PackPrice.findOne({
      vendorId: req.params.vendorId,
    }).lean();
    if (!packPrice)
      return res.status(404).json({ error: "Pack prices not found." });
    res.json(packPrice);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
