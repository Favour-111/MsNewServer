const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Vendor = require("../models/Vendor");
const Product = require("../models/Product");
const Withdrawal = require("../models/Withdrawal");
const mongoose = require("mongoose");
const { getIO } = require("../socket");

// Replace with your secret key (store in environment variable)
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// ✅ SIGN UP route (requires vendor image)
router.post("/signup", async (req, res) => {
  try {
    const { storeName, university, email, password, image } = req.body;

    // Check required fields
    if (!storeName || !university || !email || !password || !image) {
      return res
        .status(400)
        .json({ message: "All fields are required (including image)" });
    }

    // Check if email already exists
    const existingVendor = await Vendor.findOne({ email });
    if (existingVendor) {
      return res.status(400).json({ message: "Email already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Upload image to Cloudinary
    const { cloudinary } = require("../config/cloudinary");
    let uploaded;
    try {
      uploaded = await cloudinary.uploader.upload(image, {
        folder: "mealsection/vendors",
        transformation: [
          { width: 512, height: 512, crop: "fill", gravity: "auto" },
        ],
      });
    } catch (e) {
      console.error("Cloudinary upload error:", e?.message || e);
      return res.status(500).json({ message: "Failed to upload image" });
    }

    // Create vendor
    const newVendor = new Vendor({
      storeName,
      university,
      email,
      password: hashedPassword,
      image: uploaded.secure_url,
    });

    await newVendor.save();

    res
      .status(201)
      .json({ message: "Vendor registered successfully", newVendor });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ LOGIN route
router.post("/login", async (req, res) => {
  try {
    const { email, password, fcmToken } = req.body;

    // Check required fields
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    // Find vendor
    const vendor = await Vendor.findOne({ email });
    if (!vendor) {
      return res.status(404).json({ message: "Vendor not found" });
    }

    // Compare passwords
    const isMatch = await bcrypt.compare(password, vendor.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Update FCM token if provided
    if (fcmToken && fcmToken !== vendor.fcmToken) {
      vendor.fcmToken = fcmToken;
      await vendor.save();
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: vendor._id, email: vendor.email, role: vendor.role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.status(200).json({
      message: "Login successful",
      token,
      vendor: {
        id: vendor._id,
        storeName: vendor.storeName,
        email: vendor.email,
        role: vendor.role,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

router.get("/all", async (req, res) => {
  try {
    const allVendor = await Vendor.find();
    if (allVendor) {
      res.send(allVendor);
    } else {
      res.send({
        status: false,
        message: "error fetching vendors",
      });
    }
  } catch (error) {
    console.log(error);
  }
});

router.post("/add", async (req, res) => {
  try {
    const { vendorId, title, price, category, image } = req.body;

    if (!vendorId || !title || !price || !category || !image) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Validate vendor exists
    const vendor = await Vendor.findById(vendorId);
    if (!vendor) {
      return res.status(404).json({ message: "Vendor not found" });
    }

    const newProduct = await Product.create({
      vendorId,
      title,
      price,
      category,
      image,
    });

    res.status(201).json({ message: "Product added successfully", newProduct });
    try {
      getIO().emit("products:new", { product: newProduct });
    } catch {}
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error", error });
  }
});

// 🟡 Edit product
router.put("/edit/:id", async (req, res) => {
  try {
    const { vendorId, title, price, category, image } = req.body;
    const productId = req.params.id;

    // Basic validation
    if (!vendorId || !title || !price || !category || !image) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Find and update the product
    const updatedProduct = await Product.findByIdAndUpdate(
      productId,
      { vendorId, title, price, category, image },
      { new: true } // returns the updated document
    );

    if (!updatedProduct) {
      return res.status(404).json({ message: "Product not found" });
    }

    try {
      getIO().emit("products:updated", { product: updatedProduct });
    } catch {}
    res.json({
      message: "Product updated successfully",
      updatedProduct,
    });
  } catch (error) {
    console.error("Error updating product:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

// ✅ Get all products (optional filter by vendor)
router.get("/allProduct", async (req, res) => {
  try {
    const products = await Product.find();
    if (products) {
      res.send(products);
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error", error });
  }
});

// ✅ Update product
router.put("/update/:id", async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
    });
    if (!product) return res.status(404).json({ message: "Product not found" });

    res.status(200).json({ message: "Product updated", product });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

// ✅ Delete product
router.delete("/delete/:id", async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    if (!product) return res.status(404).json({ message: "Product not found" });

    res.status(200).json({ message: "Product deleted successfully" });
    try {
      getIO().emit("products:deleted", { productId: req.params.id });
    } catch {}
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

// ✅ Toggle availability
router.put("/toggle/:id", async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: "Product not found" });

    product.available = !product.available;
    await product.save();

    res
      .status(200)
      .json({ message: "Availability updated", available: product.available });
    try {
      getIO().emit("products:toggled", {
        productId: product._id,
        available: product.available,
      });
    } catch {}
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

router.post("/withdrawals", async (req, res) => {
  const session = await mongoose.startSession();

  try {
    const { vendorId, vendorName, amount } = req.body;

    if (!vendorId || !vendorName || !amount)
      return res.status(400).json({ message: "Missing required fields" });

    await session.withTransaction(async () => {
      const vendor = await Vendor.findById(vendorId).session(session);
      if (!vendor) throw new Error("Vendor not found");

      if (vendor.availableBal < amount) {
        throw new Error("Insufficient balance");
      }

      // Deduct temporarily
      vendor.availableBal -= amount;
      await vendor.save({ session });

      const withdrawal = new Withdrawal({
        vendorId,
        vendorName,
        amount,
        status: null, // pending
      });

      await withdrawal.save({ session });

      res.status(201).json({
        message: "Vendor withdrawal request created successfully",
        withdrawal,
      });
    });
  } catch (err) {
    console.error("Transaction error:", err);
    res.status(500).json({ message: err.message || "Server error" });
  } finally {
    session.endSession();
  }
});

// 🟡 Update withdrawal status (true / false)
router.put("/withdrawals/:id/status", async (req, res) => {
  const session = await mongoose.startSession();

  try {
    const { status } = req.body; // true or false
    if (typeof status !== "boolean")
      return res.status(400).json({ message: "Status must be boolean" });

    await session.withTransaction(async () => {
      const withdrawal = await Withdrawal.findById(req.params.id).session(
        session
      );
      if (!withdrawal) throw new Error("Withdrawal not found");

      const vendor = await Vendor.findById(withdrawal.vendorId).session(
        session
      );
      if (!vendor) throw new Error("Vendor not found");

      if (status === true) {
        // ✅ Approved
        withdrawal.status = true;
      } else {
        // ❌ Rejected → refund
        vendor.availableBal += withdrawal.amount;
        withdrawal.status = false;
        await vendor.save({ session });
      }

      await withdrawal.save({ session });

      res.status(200).json({
        message:
          status === true
            ? "Vendor withdrawal approved successfully"
            : "Vendor withdrawal rejected and refunded",
        withdrawal,
      });
    });
  } catch (err) {
    console.error("Transaction error:", err);
    res.status(500).json({ message: err.message || "Server error" });
  } finally {
    session.endSession();
  }
});

// 🟢 Get all withdrawals (for admin dashboard)
router.get("/withdrawals", async (req, res) => {
  try {
    const withdrawals = await Withdrawal.find()
      .populate("vendorId", "fullName email")
      .sort({ createdAt: -1 });
    res.json({ withdrawals });
  } catch (err) {
    console.error("Error fetching withdrawals:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// 🔴 Delete a withdrawal
router.delete("/withdrawals/:id", async (req, res) => {
  try {
    const deleted = await Withdrawal.findByIdAndDelete(req.params.id);
    if (!deleted)
      return res.status(404).json({ message: "Withdrawal not found" });

    res.json({ message: "Withdrawal deleted successfully" });
  } catch (err) {
    console.error("Error deleting withdrawal:", err);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;

// ===== Vendor Activation Management =====
// Activate a vendor
router.patch("/:id/activate", async (req, res) => {
  try {
    const { id } = req.params;
    const vendor = await Vendor.findByIdAndUpdate(
      id,
      { Active: "true" },
      { new: true }
    );
    if (!vendor) return res.status(404).json({ message: "Vendor not found" });
    return res.json({ message: "Vendor activated", vendor });
  } catch (err) {
    console.error("Activate vendor error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// Deactivate a vendor
router.patch("/:id/deactivate", async (req, res) => {
  try {
    const { id } = req.params;
    const vendor = await Vendor.findByIdAndUpdate(
      id,
      { Active: "false" },
      { new: true }
    );
    if (!vendor) return res.status(404).json({ message: "Vendor not found" });
    return res.json({ message: "Vendor deactivated", vendor });
  } catch (err) {
    console.error("Deactivate vendor error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// Optional: Set Active explicitly via body { active: true|false|"true"|"false" }
router.patch("/:id/active", async (req, res) => {
  try {
    const { id } = req.params;
    let { active } = req.body;
    // Normalize to string "true" or "false" to match schema
    const normalized =
      (typeof active === "boolean" ? active : String(active))
        .toString()
        .toLowerCase() === "true"
        ? "true"
        : "false";

    const vendor = await Vendor.findByIdAndUpdate(
      id,
      { Active: normalized },
      { new: true }
    );
    if (!vendor) return res.status(404).json({ message: "Vendor not found" });
    return res.json({
      message: `Vendor ${normalized === "true" ? "activated" : "deactivated"}`,
      vendor,
    });
  } catch (err) {
    console.error("Set active vendor error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});
