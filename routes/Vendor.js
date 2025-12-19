// =============== FORGOT PASSWORD FOR VENDOR ===============
const nodemailer = require("nodemailer");
const crypto = require("crypto");

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
      valid: null, // must be approved by manager
    });

    await newVendor.save();
    res
      .status(201)
      .json({ message: "Vendor registered successfully", newVendor });
    // Add socket or notification logic here if needed, using setImmediate
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});
// PATCH /vendors/:id/approve
router.patch("/:id/approve", async (req, res) => {
  try {
    const { valid } = req.body;
    const vendor = await Vendor.findByIdAndUpdate(
      req.params.id,
      { valid },
      { new: true }
    );
    if (!vendor) return res.status(404).json({ message: "Vendor not found" });
    res.json({ message: "Vendor approval updated", vendor });
  } catch (e) {
    res.status(500).json({ message: "Error updating vendor approval" });
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

    // Check approval status
    if (vendor.valid !== true) {
      return res.status(403).json({
        message:
          vendor.valid === false
            ? "Your account was not approved. Contact support."
            : "Waiting for manager approval. You cannot login yet.",
      });
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
    // Add socket or notification logic here if needed, using setImmediate
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// =============== FORGOT PASSWORD FOR VENDOR ===============
// Save or update vendor bank account info
router.post("/:id/bank-info", async (req, res) => {
  try {
    const { id } = req.params;
    const { bankAccountNumber, bankAccountName, bankName } = req.body;
    if (!bankAccountNumber || !bankAccountName || !bankName) {
      return res
        .status(400)
        .json({ message: "All bank info fields are required" });
    }
    const vendor = await Vendor.findByIdAndUpdate(
      id,
      { bankAccountNumber, bankAccountName, bankName },
      { new: true }
    );
    if (!vendor) return res.status(404).json({ message: "Vendor not found" });
    res.json({ message: "Bank info saved", vendor });
  } catch (err) {
    console.error("Save bank info error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// Fetch vendor bank account info
router.get("/:id/bank-info", async (req, res) => {
  try {
    const { id } = req.params;
    const vendor = await Vendor.findById(id);
    if (!vendor) return res.status(404).json({ message: "Vendor not found" });
    // Always return valid fields, even if not set
    const bankAccountNumber = vendor.bankAccountNumber || "";
    const bankAccountName = vendor.bankAccountName || "";
    const bankName = vendor.bankName || "";
    res.json({ bankAccountNumber, bankAccountName, bankName });
  } catch (err) {
    console.error("Fetch bank info error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});
// POST /vendors/forgot-password
router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;

  try {
    const vendor = await Vendor.findOne({ email });
    if (!vendor) return res.status(404).json({ message: "Vendor not found" });

    // Generate a secure token
    const resetToken = crypto.randomBytes(32).toString("hex");
    const hashedToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    // Store hashed token and expiry in DB (expires in 1 hour)
    vendor.resetPasswordToken = hashedToken;
    vendor.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await vendor.save();

    // Construct reset link
    const resetLink = `${process.env.VENDOR_APP_URL}/reset-password/${resetToken}`;

    // Use emailService to send the reset email via Brevo API
    const { sendEmailViaBrevoApi } = require("../services/emailService");
    await sendEmailViaBrevoApi({
      to: vendor.email,
      subject: "Reset Your Vendor Password",
      html: `
        <div style="background: #fff7f2; min-height: 100vh; padding: 0; margin: 0; font-family: 'Segoe UI', Arial, sans-serif;">
          <div style="max-width: 440px; margin: 56px auto 32px auto; background: #fff; border-radius: 24px; box-shadow: 0 6px 32px rgba(201,26,26,0.10); border: 1.5px solid #f3e5e5; padding: 44px 32px 36px 32px;">
            <div style="display: flex; flex-direction: column; justify-content: center; align-items: center;">
              <img src="https://github.com/Favour-111/my-asset/blob/main/images%20(2).jpeg?raw=true" alt="MealSection Logo" style="width: 150px; " />
              </div>
              <p style="text-align: center; color: #b71c1c; font-size: 13px; font-weight: 500; margin-bottom: 10px;">Food Delivery for Universities</p>
            <h2 style="font-size: 1.22rem;  font-weight: 700; margin-bottom: 12px; text-align: center;">Hi ${
              vendor.storeName
            } 👋</h2>
            <p style="color: #787878; font-size: 13px; margin-bottom: 24px; text-align: center;">We received a request to reset your vendor account password. Click the button below to set a new password. If you did not request this, you can safely ignore this email.</p>
            <div style="text-align: center; margin-bottom: 24px;">
              <a href="${resetLink}" style="display: inline-block; background: linear-gradient(90deg, #9e0505 0%, #c91a1a 100%); color: #fff; font-weight: 500; padding: 16px 40px; border-radius: 14px; text-decoration: none; font-size: 13px; box-shadow: 0 2px 12px rgba(201,26,26,0.13); transition: background 0.2s, transform 0.2s;">Reset Password</a>
            </div>
            <p style="color: #888; font-size: 0.99rem; margin-top: 0; text-align: center;">This link will expire in 1 hour for your security.</p>
            <hr style="border: none; border-top: 1.5px solid #f3e5e5; margin: 28px 0 16px 0;" />
            <p style="color: #b71c1c; font-size: 0.99rem; margin: 0; text-align: center;">Questions? <a href="mailto:mealsection@gmail.com" style="color: #c91a1a; text-decoration: underline;">mealsection@gmail.com</a></p>
            <a href="https://favour-111.github.io/my-portfolio/" target="_blank" rel="noopener" style="color: #bbb; font-size: 0.89rem; margin-top: 16px; text-align: center; text-decoration: underline;">&copy; ${new Date().getFullYear()} Horbah's Tech. All rights reserved.</a>
          </div>
        </div>
      `,
    });

    res.json({ message: "Password reset link sent to your email" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// POST /vendor/reset-password/:token
router.post("/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  if (!newPassword)
    return res.status(400).json({ message: "New password is required" });

  try {
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const vendor = await Vendor.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() }, // token not expired
    });

    if (!vendor)
      return res.status(400).json({ message: "Invalid or expired token" });

    // Update password
    vendor.password = await bcrypt.hash(newPassword, 10);

    // Remove reset token & expiry
    vendor.resetPasswordToken = undefined;
    vendor.resetPasswordExpires = undefined;

    await vendor.save();

    // Optionally generate JWT
    const jwtToken = jwt.sign(
      { id: vendor._id, email: vendor.email, role: vendor.role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ message: "Password reset successfully", token: jwtToken });
  } catch (err) {
    console.error(err);
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

    if (!vendorId || !title || !price || !category) {
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
    setImmediate(() => {
      try {
        getIO().emit("products:new", { product: newProduct });
      } catch {}
    });
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
    if (!vendorId || !title || !category) {
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

    setImmediate(() => {
      try {
        getIO().emit("products:updated", { product: updatedProduct });
      } catch {}
    });
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
    const { vendorId } = req.query;
    let products;
    if (vendorId) {
      products = await Product.find({ vendorId });
    } else {
      products = await Product.find();
    }
    res.send(products);
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
    setImmediate(() => {
      try {
        getIO().emit("products:deleted", { productId: req.params.id });
      } catch {}
    });
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
    setImmediate(() => {
      try {
        getIO().emit("products:toggled", {
          productId: product._id,
          available: product.available,
        });
      } catch {}
    });
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
    res.json({ message: "Vendor activated", vendor });
    // Add socket or notification logic here if needed, using setImmediate
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
    res.json({ message: "Vendor deactivated", vendor });
    // Add socket or notification logic here if needed, using setImmediate
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
    res.json({
      message: `Vendor ${normalized === "true" ? "activated" : "deactivated"}`,
      vendor,
    });
    // Add socket or notification logic here if needed, using setImmediate
  } catch (err) {
    console.error("Set active vendor error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// Delete a vendor
router.delete("/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const vendor = await Vendor.findByIdAndDelete(id);
    if (!vendor) return res.status(404).json({ message: "Vendor not found" });

    // Optionally delete all products associated with this vendor
    await Product.deleteMany({ vendorId: id });

    res.json({ message: "Vendor deleted successfully", vendor });
    // Add socket or notification logic here if needed, using setImmediate
  } catch (err) {
    console.error("Delete vendor error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
