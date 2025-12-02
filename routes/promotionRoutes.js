const express = require("express");
const router = express.Router();
const Promotion = require("../models/Promotion");
const Vendor = require("../models/Vendor");
const { getIO } = require("../socket");

// ✅ GET all promotions (with optional university filter)
router.get("/", async (req, res) => {
  try {
    const { university, status } = req.query;
    let filter = {};
    if (university) filter.university = university;
    if (status) filter.status = status;
    // Use .lean() for faster query
    const promotions = await Promotion.find(filter)
      .populate("vendorId", "storeName email Active")
      .sort({ createdAt: -1 })
      .lean();
    res.status(200).json({ promotions });
  } catch (error) {
    console.error("Error fetching promotions:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

// ✅ GET single promotion by ID
router.get("/:id", async (req, res) => {
  try {
    const promotion = await Promotion.findById(req.params.id).populate(
      "vendorId",
      "storeName email university"
    );

    if (!promotion) {
      return res.status(404).json({ message: "Promotion not found" });
    }

    res.status(200).json({ promotion });
  } catch (error) {
    console.error("Error fetching promotion:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

// ✅ CREATE new promotion
router.post("/", async (req, res) => {
  try {
    const {
      vendorId,
      vendorName,
      university,
      header,
      text,
      discount,
      duration,
      endDate,
      status,
      featured,
    } = req.body;

    // Validate required fields
    if (
      !vendorId ||
      !vendorName ||
      !university ||
      !header ||
      !text ||
      !discount ||
      !duration
    ) {
      return res
        .status(400)
        .json({ message: "All required fields must be provided" });
    }

    // Verify vendor exists
    const vendor = await Vendor.findById(vendorId);
    if (!vendor) {
      return res.status(404).json({ message: "Vendor not found" });
    }

    const newPromotion = await Promotion.create({
      vendorId,
      vendorName,
      university,
      header,
      text,
      discount,
      duration,
      endDate: endDate || null,
      status: status || "active",
      featured: featured || false,
    });

    const populatedPromotion = await Promotion.findById(
      newPromotion._id
    ).populate("vendorId", "storeName email Active");

    res.status(201).json({
      message: "Promotion created successfully",
      promotion: populatedPromotion,
    });
    setImmediate(() => {
      try {
        getIO().emit("promotions:new", { promotion: populatedPromotion });
      } catch {}
    });
  } catch (error) {
    console.error("Error creating promotion:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

// ✅ UPDATE promotion
router.put("/:id", async (req, res) => {
  try {
    const {
      vendorId,
      vendorName,
      university,
      header,
      text,
      discount,
      duration,
      endDate,
      status,
      featured,
    } = req.body;

    const updatedPromotion = await Promotion.findByIdAndUpdate(
      req.params.id,
      {
        vendorId,
        vendorName,
        university,
        header,
        text,
        discount,
        duration,
        endDate,
        status,
        featured,
      },
      { new: true, runValidators: true }
    ).populate("vendorId", "storeName email Active");

    if (!updatedPromotion) {
      return res.status(404).json({ message: "Promotion not found" });
    }

    res.status(200).json({
      message: "Promotion updated successfully",
      promotion: updatedPromotion,
    });
    setImmediate(() => {
      try {
        getIO().emit("promotions:updated", { promotion: updatedPromotion });
      } catch {}
    });
  } catch (error) {
    console.error("Error updating promotion:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

// ✅ UPDATE promotion status only
router.patch("/:id/status", async (req, res) => {
  try {
    const { status } = req.body;

    if (!["active", "inactive", "completed"].includes(status)) {
      return res.status(400).json({
        message: "Invalid status. Must be: active, inactive, or completed",
      });
    }

    const updatedPromotion = await Promotion.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    ).populate("vendorId", "storeName email Active");

    if (!updatedPromotion) {
      return res.status(404).json({ message: "Promotion not found" });
    }

    res.status(200).json({
      message: "Promotion status updated successfully",
      promotion: updatedPromotion,
    });
    setImmediate(() => {
      try {
        getIO().emit("promotions:status-changed", {
          promotionId: updatedPromotion._id,
          status: updatedPromotion.status,
        });
      } catch {}
    });
  } catch (error) {
    console.error("Error updating promotion status:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

// ✅ TOGGLE featured status
router.patch("/:id/featured", async (req, res) => {
  try {
    const promotion = await Promotion.findById(req.params.id);

    if (!promotion) {
      return res.status(404).json({ message: "Promotion not found" });
    }

    promotion.featured = !promotion.featured;
    await promotion.save();

    const populatedPromotion = await Promotion.findById(promotion._id).populate(
      "vendorId",
      "storeName email Active"
    );

    res.status(200).json({
      message: "Featured status toggled successfully",
      promotion: populatedPromotion,
    });
    setImmediate(() => {
      try {
        getIO().emit("promotions:featured-toggled", {
          promotionId: populatedPromotion._id,
          featured: populatedPromotion.featured,
        });
      } catch {}
    });
  } catch (error) {
    console.error("Error toggling featured status:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

// ✅ DELETE promotion
router.delete("/:id", async (req, res) => {
  try {
    const deletedPromotion = await Promotion.findByIdAndDelete(req.params.id);

    if (!deletedPromotion) {
      return res.status(404).json({ message: "Promotion not found" });
    }

    res.status(200).json({
      message: "Promotion deleted successfully",
      promotionId: deletedPromotion._id,
    });
    setImmediate(() => {
      try {
        getIO().emit("promotions:deleted", {
          promotionId: deletedPromotion._id,
        });
      } catch {}
    });
  } catch (error) {
    console.error("Error deleting promotion:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

module.exports = router;
