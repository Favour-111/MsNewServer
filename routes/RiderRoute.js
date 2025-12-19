const express = require("express");
const bcrypt = require("bcryptjs");
const Rider = require("../models/Rider");
const router = express.Router();
const RiderWithdrawal = require("../models/RiderWithdrawal");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
// ✅ SIGN UP route
router.post("/signup", async (req, res) => {
  try {
    const { userName, university, email, phoneNumber, password } = req.body;

    // Check required fields
    if (!userName || !university || !email || !phoneNumber || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Check if email already exists
    const existingUser = await Rider.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const newRider = new Rider({
      userName,
      university,
      email,
      phoneNumber,
      password: hashedPassword,
      valid: null, // must be approved by manager
    });

    await newRider.save();
    res
      .status(201)
      .json({ message: "Vendor registered successfully", newRider });
    // Add socket or notification logic here if needed, using setImmediate
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});
// PATCH /riders/:id/approve
router.patch("/:id/approve", async (req, res) => {
  try {
    const { valid } = req.body;
    const rider = await Rider.findByIdAndUpdate(
      req.params.id,
      { valid },
      { new: true }
    );
    if (!rider) return res.status(404).json({ message: "Rider not found" });
    res.json({ message: "Rider approval updated", rider });
  } catch (e) {
    res.status(500).json({ message: "Error updating rider approval" });
  }
});
// ✅ LOGIN route
router.delete("/delete-rider/:id", async (req, res) => {
  try {
    const rider = await Rider.findByIdAndDelete(req.params.id);
    if (!rider) {
      return res.status(404).json({ message: "Rider not found" });
    }
    res.json({ success: true, message: "Rider deleted successfully", rider });
    // Add socket or notification logic here if needed, using setImmediate
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
// routes/auth.js
router.post("/login", async (req, res) => {
  const { email, password, fcmToken } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: "Email and password required" });

  const rider = await Rider.findOne({ email });
  if (!rider) return res.status(404).json({ message: "Rider not found" });

  // Check approval status
  if (rider.valid !== true) {
    return res.status(403).json({
      message:
        rider.valid === false
          ? "Your account was not approved. Contact support."
          : "Waiting for manager approval. You cannot login yet.",
    });
  }

  const isMatch = await bcrypt.compare(password, rider.password);
  if (!isMatch) return res.status(401).json({ message: "Invalid credentials" });

  // Update FCM token if provided
  if (fcmToken && fcmToken !== rider.fcmToken) {
    rider.fcmToken = fcmToken;
    await rider.save();
  }

  const token = jwt.sign(
    { id: rider._id, email: rider.email, role: rider.role },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.status(200).json({
    message: "Login successful",
    token,
    rider: {
      id: rider._id,
      storeName: rider.storeName,
      email: rider.email,
      role: rider.role,
    },
  });
  // Add socket or notification logic here if needed, using setImmediate
});

router.get("/allRiders", async (req, res) => {
  try {
    // Use .lean() for faster query and only select needed fields
    const getAllRider = await Rider.find().lean();
    if (getAllRider) {
      res.send(getAllRider);
    } else {
      res.send({
        success: false,
        message: "error fetching riders",
      });
    }
  } catch (error) {
    console.log(error);
  }
});

// Middleware to simulate auth (optional)
const auth = (req, res, next) => {
  // attach riderId to req.body if needed
  next();
};

/**
 * @route   POST /api/rider-withdrawals
 * @desc    Create a rider withdrawal request
 * @access  Private
 */
router.post("/withdraw", async (req, res) => {
  const session = await mongoose.startSession();

  try {
    const { riderId, riderName, amount } = req.body;

    if (!riderId || !riderName || !amount)
      return res.status(400).json({ message: "All fields are required" });

    await session.withTransaction(async () => {
      const rider = await Rider.findById(riderId).session(session);
      if (!rider) throw new Error("Rider not found");

      if (rider.availableBal < amount) {
        throw new Error("Insufficient balance");
      }

      // Temporarily deduct balance
      rider.availableBal -= amount;
      await rider.save({ session });

      // Create withdrawal record
      const withdrawal = new RiderWithdrawal({
        riderId,
        riderName,
        amount,
        status: null, // pending
      });

      await withdrawal.save({ session });

      res.status(201).json({
        message: "Withdrawal request created successfully",
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

/**
 * @route   GET /api/rider/withdrawals
 * @desc    Get all rider withdrawals
 * @access  Private/Admin
 */
router.get("/withdraw", auth, async (req, res) => {
  try {
    const withdrawals = await RiderWithdrawal.find().sort({ date: -1 });
    res.status(200).json(withdrawals);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

/**
 * @route   PATCH /api/rider/withdrawals/:id
 * @desc    Update withdrawal status (processed/pending)
 * @access  Private/Admin
 */
// PATCH /api/riders/withdraw/rider/:id
router.patch("/withdraw/rider/:id", async (req, res) => {
  const session = await mongoose.startSession();

  try {
    const { status } = req.body; // true or false
    if (typeof status !== "boolean")
      return res.status(400).json({ message: "Status must be a boolean" });

    await session.withTransaction(async () => {
      const withdrawal = await RiderWithdrawal.findById(req.params.id).session(
        session
      );
      if (!withdrawal) throw new Error("Withdrawal not found");

      const rider = await Rider.findById(withdrawal.riderId).session(session);
      if (!rider) throw new Error("Rider not found");

      if (status === true) {
        // ✅ Approved — nothing to refund
        withdrawal.status = true;
      } else {
        // ❌ Rejected — refund
        rider.availableBal += withdrawal.amount;
        withdrawal.status = false;
        await rider.save({ session });
      }

      await withdrawal.save({ session });

      res.status(200).json({
        message:
          status === true
            ? "Withdrawal approved successfully"
            : "Withdrawal rejected and refunded",
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

module.exports = router;
