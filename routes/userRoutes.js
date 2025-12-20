// ...existing code...
// ===================== VERIFY PAYSTACK PAYMENT =====================
// POST /verify-paystack { reference, userId }

// ===================== ADMIN ADD FUNDS TO USER =====================

// POST /admin/add-funds { userId, amount }

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const Order = require("../models/Order");
const router = express.Router();
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const auth = require("../middleware/authMiddleware");
const { getIO } = require("../socket");
const Rider = require("../models/Rider");
const Vendor = require("../models/Vendor");
// // Middleware for authentication
// const auth = async (req, res, next) => {
//   const token = req.header("Authorization")?.split(" ")[1];
//   if (!token) return res.status(401).json({ message: "No token provided" });

//   try {
//     const decoded = jwt.verify(token, process.env.JWT_SECRET);
//     req.user = decoded.id;
//     next();
//   } catch (err) {
//     res.status(400).json({ message: "Invalid token" });
//   }
// };

// ===================== REGISTER =====================
router.get("/allUser", async (req, res) => {
  try {
    const users = await User.find().lean();
    if (users) {
      return res.status(201).json({ message: users });
    } else {
      res.status(201).json({ message: "error fetching users" });
    }
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
router.post("/signup", async (req, res) => {
  const { fullName, email, password, university, role } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      fullName,
      email,
      password: hashedPassword,
      university,
      role,
    });

    // Generate JWT token
    const token = jwt.sign(
      { userId: newUser._id, role: newUser.role },
      process.env.JWT_SECRET, // make sure you have JWT_SECRET in .env
      { expiresIn: "7d" }
    );

    res.status(201).json({
      message: "User registered successfully",
      user: newUser,
      token, // <-- now the frontend receives it
    });
    setImmediate(() => {
      try {
        getIO().emit("users:signedUp", {
          userId: newUser._id,
          email: newUser.email,
          role: newUser.role,
        });
      } catch {}
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
router.post("/verify-paystack", async (req, res) => {
  const { reference } = req.body;
  if (!reference) {
    return res.status(400).json({ message: "Payment reference is required" });
  }
  const { verifyPaystackPayment } = require("../services/paystackService");
  try {
    const paystackRes = await verifyPaystackPayment(reference);
    if (paystackRes.status !== true || paystackRes.data.status !== "success") {
      return res
        .status(400)
        .json({ message: "Payment not successful", verified: false });
    }
    // Only verify, do not credit wallet here. Wallet will be credited by webhook.
    res.json({ status: "success", verified: true, paystack: paystackRes });
  } catch (err) {
    console.error("❌ Error verifying paystack payment:", err);
    res
      .status(500)
      .json({ message: err.message || "Verification error", verified: false });
  }
});
router.post("/admin/add-funds", async (req, res) => {
  const { userId, amount } = req.body;
  if (!userId || typeof amount !== "number" || amount <= 0) {
    return res
      .status(400)
      .json({ message: "userId and valid amount are required" });
  }
  try {
    const user = await User.findByIdAndUpdate(
      userId,
      {
        $inc: { availableBal: amount },
        $push: {
          paymentHistory: {
            price: amount,
            type: "in",
            orderId: "AdminFund",
            date: new Date(),
          },
        },
      },
      { new: true }
    );
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json({ success: true, user });
    setImmediate(() => {
      try {
        getIO().emit("users:balanceUpdated", {
          userId: user._id,
          availableBal: user.availableBal,
        });
      } catch {}
    });
  } catch (err) {
    console.error("❌ Error adding admin funds:", err);
    res.status(500).json({ message: err.message || "Server error" });
  }
});
// ===================== ADMIN REMOVE FUNDS FROM USER =====================
// POST /admin/remove-funds { userId, amount }
router.post("/admin/remove-funds", async (req, res) => {
  const { userId, amount } = req.body;
  if (!userId || typeof amount !== "number" || amount <= 0) {
    return res
      .status(400)
      .json({ message: "userId and valid amount are required" });
  }
  try {
    const user = await User.findByIdAndUpdate(
      userId,
      {
        $inc: { availableBal: -amount },
        $push: {
          paymentHistory: {
            price: amount,
            type: "out",
            orderId: "AdminRemove",
            date: new Date(),
          },
        },
      },
      { new: true }
    );
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json({ success: true, user });
    setImmediate(() => {
      try {
        getIO().emit("users:balanceUpdated", {
          userId: user._id,
          availableBal: user.availableBal,
        });
      } catch {}
    });
  } catch (err) {
    console.error("❌ Error removing admin funds:", err);
    res.status(500).json({ message: err.message || "Server error" });
  }
});
// ===================== LOGIN =====================
router.post("/login", async (req, res) => {
  const { email, password, fcmToken } = req.body;

  try {
    // Find user by email
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid password" });

    // Update FCM token if provided
    if (fcmToken && fcmToken !== user.fcmToken) {
      user.fcmToken = fcmToken;
      await user.save();
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    // Send safe user data (omit password)
    const safeUser = {
      _id: user._id,
      fullName: user.fullName,
      email: user.email,
      university: user.university,
      role: user.role,
      availableBal: user.availableBal,
      orders: user.orders,
      paymentHistory: user.paymentHistory,
    };

    res.json({ token, user: safeUser });
    setImmediate(() => {
      try {
        getIO().emit("users:loggedIn", { userId: user._id, email: user.email });
      } catch {}
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ===================== ADD BALANCE TO USER (SuperAdmin) =====================
// ===================== DELETE USER (SuperAdmin) =====================
// DELETE /delete-user/:id
router.delete("/delete-user/:id", async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json({ success: true, message: "User deleted successfully", user });
    setImmediate(() => {
      try {
        getIO().emit("users:deleted", { userId: req.params.id });
      } catch {}
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
// POST /add-balance { userId, amount }
// POST /add-balance { userId, amount, reference }
// This endpoint now ONLY verifies payment, does NOT credit wallet. Wallet is credited by webhook.
router.post("/add-balance", async (req, res) => {
  const { userId, amount, reference } = req.body;
  if (!userId || typeof amount !== "number" || amount <= 0 || !reference) {
    return res.status(400).json({
      message: "userId, valid amount, and payment reference are required",
    });
  }
  const { verifyPaystackPayment } = require("../services/paystackService");
  let paystackRes;
  try {
    // Try Paystack verification, retry once if reference not found
    try {
      paystackRes = await verifyPaystackPayment(reference);
    } catch (err) {
      if ((err.message || "").toLowerCase().includes("reference not found")) {
        // Wait 1s and retry once
        await new Promise((resolve) => setTimeout(resolve, 1000));
        paystackRes = await verifyPaystackPayment(reference);
      } else {
        throw err;
      }
    }
    if (
      !paystackRes.status ||
      paystackRes.data.status !== "success" ||
      paystackRes.data.amount / 100 !== amount
    ) {
      // Log for debugging
      console.error("Paystack verification failed:", paystackRes);
      return res
        .status(400)
        .json({ message: "Payment verification failed or amount mismatch" });
    }
    // Do NOT credit wallet here. Only return verification status.
    return res.json({
      success: true,
      verified: true,
      message: "Payment verified. Wallet will be credited by webhook.",
    });
  } catch (err) {
    // Always log error for debugging
    console.error("❌ Error verifying payment:", err);
    // If error is reference not found, return a generic message
    if ((err.message || "").toLowerCase().includes("reference not found")) {
      return res.status(400).json({
        message:
          "Payment reference not found. Please try again in a few seconds.",
      });
    }
    res.status(500).json({ message: err.message || "Server error" });
  }
});

// ===================== PLACE ORDER =====================
// routes/yourRoutes.js (where /add-order exists)
router.post("/add-order", auth, async (req, res) => {
  const {
    subtotal,
    university,
    Address,
    PhoneNumber,
    serviceFee,
    deliveryFee,
    packs,
    deliveryNote,
    vendorNote,
  } = req.body;

  try {
    const user = await User.findById(req.user);
    if (!user) return res.status(404).json({ message: "User not found" });

    const total =
      Number(subtotal) + Number(serviceFee) + Number(deliveryFee || 0);

    if (user.availableBal < total)
      return res.status(400).json({ message: "Insufficient balance" });

    // ✅ Validate packs
    if (!Array.isArray(packs) || packs.length === 0) {
      return res.status(400).json({ message: "No packs provided" });
    }

    for (const p of packs) {
      if (!p.name)
        return res.status(400).json({ message: "Pack missing name" });
      if (!p.vendorName)
        return res.status(400).json({ message: "Pack missing vendorName" });
      if (!Array.isArray(p.items) || p.items.length === 0) {
        return res.status(400).json({
          message: `Pack \"${p.name}\" has no items Please Remove Empty pack`,
        });
      }
      // Only enforce packType if pack contains protein or carbohydrate
      const requiresPackType =
        Array.isArray(p.items) &&
        p.items.some(
          (it) =>
            it.category &&
            ["protein", "carbohydrate"].includes(it.category.toLowerCase())
        );
      if (
        requiresPackType &&
        (!p.packType || (p.packType !== "small" && p.packType !== "big"))
      ) {
        return res.status(400).json({
          message: `Pack \"${p.name}\" is missing a valid packType. Please select 'small' or 'big' for every pack containing protein or carbohydrate.`,
        });
      }
      for (const it of p.items) {
        if (it.vendorName && it.vendorName !== p.vendorName) {
          return res.status(400).json({
            message: `Item vendor mismatch in pack \"${p.name}\" — all items must belong to ${p.vendorName}`,
          });
        }
      }
    }

    // ✅ Deduct funds
    user.availableBal = Number(user.availableBal) - total;

    // ✅ Build and save order object
    const newOrder = new Order({
      userId: user._id,
      subtotal,
      university,
      Address,
      PhoneNumber,
      serviceFee,
      deliveryFee,
      deliveryNote,
      vendorNote,
      packs: packs.map((p) => ({
        name: p.name,
        vendorName: p.vendorName,
        vendorId: p.vendorId || null,
        packType: p.packType || null,
        items: (p.items || []).map((it) => ({
          name: it.name,
          price: it.price,
          quantity: it.quantity,
          image: it.image,
          vendorName: it.vendorName || p.vendorName,
          vendorId: it.vendorId || p.vendorId || null,
        })),
      })),
      currentStatus: "Pending",
      rider: "Not assigned",
    });
    await newOrder.save();
    user.orders.push(newOrder._id);
    await user.save();
    const pushedOrder = newOrder;

    // ✅ Record payment
    if (!Array.isArray(user.paymentHistory)) {
      user.paymentHistory = [];
    }
    user.paymentHistory.push({
      orderId: String(pushedOrder._id),
      price: total,
      type: "out",
      date: new Date(),
    });
    await user.save();

    res
      .status(201)
      .json({ message: "Order placed successfully", order: pushedOrder });

    setImmediate(() => {
      try {
        getIO().emit("orders:new", {
          order: pushedOrder,
          user: {
            id: user._id,
            email: user.email,
            fullName: user.fullName,
            university: user.university,
          },
        });
      } catch {}
    });

    // ✅ Send push notifications to vendors
    try {
      const {
        notifyVendorNewOrder,
      } = require("../services/notificationService");
      const { sendVendorNewOrderEmail } = require("../services/emailService");
      const Vendor = require("../models/Vendor");

      // Group items by vendor to send single notification per vendor
      const vendorMap = new Map();

      for (const pack of packs) {
        if (pack.vendorId || pack.vendorName) {
          const vendorKey = pack.vendorId || pack.vendorName;
          if (!vendorMap.has(vendorKey)) {
            vendorMap.set(vendorKey, {
              vendorId: pack.vendorId,
              vendorName: pack.vendorName,
              itemCount: 0,
              totalAmount: 0,
            });
          }
          const vendorData = vendorMap.get(vendorKey);
          vendorData.itemCount += pack.items.length;
          vendorData.totalAmount += pack.items.reduce(
            (sum, item) => sum + Number(item.price) * Number(item.quantity),
            0
          );
        }
      }

      // Send notification to each vendor (both FCM and Email)
      for (const [key, data] of vendorMap) {
        let vendor = null;

        if (data.vendorId) {
          vendor = await Vendor.findById(data.vendorId);
        } else if (data.vendorName) {
          vendor = await Vendor.findOne({ storeName: data.vendorName });
        }

        if (vendor) {
          const orderInfo = {
            orderId: pushedOrder._id.toString(),
            itemCount: data.itemCount,
            total: data.totalAmount,
            userName: user.fullName,
            address: Address,
          };

          // Send FCM notification (if token available)
          if (vendor.fcmToken) {
            await notifyVendorNewOrder(vendor, orderInfo);
          }

          // ✅ Send Email notification (more reliable, works on all devices)
          await sendVendorNewOrderEmail(vendor, orderInfo);
        }
      }
    } catch (notifErr) {
      console.error("Error sending vendor notifications:", notifErr);
      // Don't fail the order if notification fails
    }
  } catch (err) {
    console.error("Error adding order:", err);
    res.status(500).json({ message: err.message });
  }
});

//getting all orders
router.get("/orders", async (req, res) => {
  try {
    // Use .lean() and only select needed fields for speed
    // Add pagination support
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;
    // Only select fields needed by the frontend
    const total = await Order.countDocuments();
    const orders = await Order.find(
      {},
      {
        subtotal: 1,
        serviceFee: 1,
        deliveryFee: 1,
        university: 1,
        Address: 1,
        PhoneNumber: 1,
        deliveryNote: 1,
        vendorNote: 1,
        packs: 1,
        currentStatus: 1,
        rider: 1,
        userId: 1,
        createdAt: 1,
        updatedAt: 1,
        messages: 1,
      }
    )
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .populate({ path: "userId", select: "fullName email" })
      .lean();
    const allOrders = orders.map((order) => ({
      ...order,
      userName: order.userId?.fullName,
      userEmail: order.userId?.email,
    }));
    res.json({ orders: allOrders, total });
  } catch (err) {
    console.error("Error fetching all orders:", err);
    res.status(500).json({ message: err.message });
  }
});

router.put("/orders/:orderId/vendor/:vendorId/accept", async (req, res) => {
  try {
    const { accepted } = req.body;
    const { orderId, vendorId } = req.params;

    console.log("📦 Accept/Reject Request:", { orderId, vendorId, accepted });

    const order = await Order.findById(orderId);
    if (!order) return res.status(404).json({ message: "Order not found" });
    const user = await User.findById(order.userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    // ✅ INPUT VALIDATION
    if (typeof accepted !== "boolean") {
      return res.status(400).json({ message: "accepted must be a boolean" });
    }

    // ✅ CRITICAL SECURITY CHECK: Verify vendor exists BEFORE processing payment
    const vendor = await Vendor.findById(vendorId);
    if (!vendor) return res.status(404).json({ message: "Vendor not found" });

    // ✅ Find the specific pack belonging to this vendor
    const vendorPack = order.packs.find((pack) => {
      const packVendorId =
        typeof pack.vendorId === "object" && pack.vendorId.toString
          ? pack.vendorId.toString()
          : String(pack.vendorId);
      const paramVendorId = String(vendorId);
      return packVendorId === paramVendorId;
    });

    if (!vendorPack) {
      return res.status(400).json({
        message: "Vendor pack not found in this order",
      });
    }

    // ✅ IDEMPOTENCY CHECK: If pack already has same decision, don't process again
    if (vendorPack.accepted === accepted) {
      console.log(
        `⚠️  Idempotent request: pack already marked as ${
          accepted ? "accepted" : "rejected"
        }`
      );
      return res.json({
        message: `Pack already marked as ${accepted ? "accepted" : "rejected"}`,
        packs: order.packs,
      });
    }

    let packsUpdated = 0;
    let vendorName = "";
    let vendorItemsTotal = 0;
    // Find the specific pack for this vendor and calculate its subtotal only
    order.packs.forEach((pack) => {
      const packVendorId =
        typeof pack.vendorId === "object" && pack.vendorId.toString
          ? pack.vendorId.toString()
          : String(pack.vendorId);
      const paramVendorId = String(vendorId);
      if (packVendorId === paramVendorId) {
        pack.accepted = accepted;
        if (!vendorName) vendorName = pack.vendorName;
        packsUpdated++;
        // Use the order's subtotal property directly for vendorItemsTotal
        if (typeof order.subtotal === "number") {
          vendorItemsTotal = order.subtotal;
        } else {
          // fallback: if subtotal is missing, default to 0
          vendorItemsTotal = 0;
        }
      }
    });

    console.log(
      `✅ Updated ${packsUpdated} packs for vendor ${vendorName}, items total: ₦${vendorItemsTotal}`
    );

    // ✅ PAYMENT LOGIC: Only process if vendor ACCEPTS (not on rejection)
    if (accepted === true) {
      // ...existing code for accepting...
      const oldBalance = vendor.availableBal || 0;
      vendor.availableBal = oldBalance + vendorItemsTotal;
      if (!vendor.paymentHistory) vendor.paymentHistory = [];
      vendor.paymentHistory.push({
        orderId: String(orderId),
        amount: vendorItemsTotal,
        type: "in",
        date: new Date(),
        description: `Order acceptance - ${vendorPack.name || "items"}`,
        previousBalance: oldBalance,
        newBalance: vendor.availableBal,
      });
      await vendor.save();
    } else {
      // ✅ Refund user when order is rejected
      // Check if ALL packs have been rejected (none accepted)
      const allPacksRejected = order.packs.every(
        (pack) => pack.accepted === false
      );
      if (allPacksRejected) {
        const refundAmount =
          Number(order.subtotal || 0) +
          Number(order.serviceFee || 0) +
          Number(order.deliveryFee || 0);
        user.availableBal = Number(user.availableBal || 0) + refundAmount;
        if (user && Array.isArray(user.paymentHistory)) {
          user.paymentHistory.push({
            orderId: String(order._id),
            price: refundAmount,
            type: "in",
            date: new Date(),
            description: "Order rejection refund - all packs declined",
          });
        }
        await user.save();
        order.currentStatus = "Cancelled";
        console.log(
          `💰 Refunded ₦${refundAmount} to user ${user.fullName} (all packs rejected)`
        );
        // ✅ Send email to customer about order rejection and refund asynchronously
        setImmediate(async () => {
          try {
            const {
              sendCustomerOrderRejectedEmail,
            } = require("../services/emailService");
            await sendCustomerOrderRejectedEmail(user, {
              orderId: orderId,
              refundAmount: refundAmount,
              vendorName: vendorName,
            });
          } catch (emailErr) {
            console.error("Error sending rejection email:", emailErr);
          }
        });
      }
    }

    await order.save();

    res.json({
      message: `All packs for vendor '${
        vendorName || vendorId
      }' updated and balance added`,
      packs: order.packs,
    });
    try {
      getIO().emit("vendors:packsUpdated", {
        orderId,
        vendorId,
        vendorName,
        accepted,
        packs: order.packs,
      });
      // ✅ Also emit order status change if cancelled
      if (order.currentStatus === "Cancelled") {
        getIO().emit("orders:status", { orderId, currentStatus: "Cancelled" });
      }
    } catch {}

    // ✅ Send push notifications to all riders
    try {
      const {
        notifyAllRidersOrderAccepted,
        notifyAllRidersOrderRejected,
      } = require("../services/notificationService");

      if (accepted) {
        // Notify all riders that order is ready for pickup
        await notifyAllRidersOrderAccepted(order.university, {
          orderId: orderId,
          vendorName: vendorName,
          address: order.Address,
          total: vendorItemsTotal,
        });
      } else {
        // Notify all riders that order was rejected
        await notifyAllRidersOrderRejected(order.university, {
          orderId: orderId,
          vendorName: vendorName,
        });
      }
    } catch (notifErr) {
      console.error("Error sending rider notifications:", notifErr);
      // Don't fail the request if notification fails
    }

    // ✅ Send email notifications to riders and customer when vendor accepts
    try {
      const {
        sendRidersNewOrderAvailableEmail,
        sendCustomerOrderUpdateEmail,
      } = require("../services/emailService");

      if (accepted) {
        // Check if all packs are accepted (order is fully ready)
        const allPacksAccepted = order.packs.every(
          (pack) => pack.accepted === true
        );

        if (allPacksAccepted) {
          // Notify all riders in the same university that order is ready
          const ridersInUniversity = await Rider.find({
            university: order.university,
          });
          if (ridersInUniversity && ridersInUniversity.length > 0) {
            await sendRidersNewOrderAvailableEmail(ridersInUniversity, {
              orderId: orderId,
              vendorName: vendorName,
              address: order.Address,
              university: order.university,
              deliveryFee: order.deliveryFee || 0,
            });
          }

          // Notify customer that all vendors have accepted
          await sendCustomerOrderUpdateEmail(user, {
            orderId: orderId,
            currentStatus: "ready",
            riderAssigned: false,
          });
        }
      }
    } catch (emailErr) {
      console.error("Error sending emails:", emailErr);
      // Don't fail the request if email fails
    }
  } catch (error) {
    console.error("Error updating packs:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});
// PUT /api/orders/:id/assign-rider
router.put("/orders/:id/assign-rider", async (req, res) => {
  try {
    const { rider } = req.body; // rider name or ID
    const orderId = req.params.id;

    const order = await Order.findById(orderId);
    if (!order) return res.status(404).json({ message: "Order not found" });
    order.rider = rider;
    await order.save();
    res.json({ message: "Rider assigned successfully", order });

    // Run notifications asynchronously
    setImmediate(async () => {
      try {
        const {
          sendRiderAssignmentEmail,
        } = require("../services/emailService");
        const riderDoc = await Rider.findById(rider);
        if (riderDoc && riderDoc.email) {
          await sendRiderAssignmentEmail(riderDoc, {
            orderId,
            address: order.Address,
            university: order.university,
            deliveryFee: order.deliveryFee,
          });
        }
      } catch (emailErr) {
        console.error("Error sending rider email:", emailErr);
      }
      try {
        getIO().emit("orders:assignRider", { orderId, rider });
      } catch (socketErr) {
        console.error("Error emitting assignRider socket event:", socketErr);
      }
    });
  } catch (err) {
    console.error("Error assigning rider:", err);
    res.status(500).json({ message: "Server error" });
  }
});
//update staus// routes/orders.js (or wherever you have it)
router.put("/orders/:id/updateStatus", async (req, res) => {
  try {
    const { currentStatus } = req.body;
    const orderId = req.params.id;

    const order = await Order.findById(orderId);
    if (!order) return res.status(404).json({ message: "Order not found" });
    order.currentStatus = currentStatus;
    await order.save();
    res.json({ message: "Status updated successfully", order });
    try {
      getIO().emit("orders:status", { orderId, currentStatus });
    } catch {}

    // Run notifications/emails asynchronously
    setImmediate(async () => {
      // If delivered, add 50% of delivery fee to rider's availableBal
      if (currentStatus === "Delivered") {
        try {
          const rider = await Rider.findById(order.rider); // assuming order.rider = riderId
          if (rider) {
            const riderShare = (order.deliveryFee || 0) * 0.5; // 50% of delivery fee
            rider.availableBal = (rider.availableBal || 0) + riderShare;
            await rider.save();
          }
        } catch (err) {
          console.error("Error updating rider balance:", err);
        }
      }

      // If processing (rider picked up order), notify the user
      if (currentStatus === "Processing") {
        try {
          const {
            notifyUserOrderPickedUp,
          } = require("../services/notificationService");
          const rider = await Rider.findById(order.rider);
          if (rider) {
            await notifyUserOrderPickedUp(user, {
              orderId: orderId,
              riderName: rider.userName || "your rider",
            });

            // ✅ Send email to customer that rider has picked up their order
            const {
              sendCustomerRiderPickedOrderEmail,
            } = require("../services/emailService");
            await sendCustomerRiderPickedOrderEmail(
              user,
              {
                orderId: orderId,
                address: order.Address,
              },
              rider.userName || "Your Rider"
            );
          }
        } catch (notifErr) {
          console.error("Error sending user notification:", notifErr);
          // Don't fail the request if notification fails
        }
      }

      // ✅ Send email notification to customer about order status change
      try {
        const {
          sendCustomerOrderUpdateEmail,
        } = require("../services/emailService");
        await sendCustomerOrderUpdateEmail(user, {
          orderId,
          currentStatus,
          riderAssigned: order.rider && order.rider !== "Not assigned",
        });
      } catch (emailErr) {
        console.error("Error sending customer email:", emailErr);
      }
    });
  } catch (err) {
    console.error("Error updating status:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// POST /api/orders/:id/message
router.post("/orders/:id/message", async (req, res) => {
  try {
    const { message } = req.body;
    const orderId = req.params.id;

    if (!message || message.trim() === "") {
      return res.status(400).json({ message: "Message cannot be empty" });
    }

    const order = await Order.findById(orderId);
    if (!order) return res.status(404).json({ message: "Order not found" });
    if (!order.messages) order.messages = [];
    order.messages.push({
      text: message,
      fromAdmin: true,
      createdAt: new Date(),
    });
    await order.save();
    res.status(200).json({
      message: "Message sent successfully",
      order,
    });
    try {
      getIO().emit("orders:message", { orderId, message });
    } catch {}
  } catch (err) {
    console.error("Error sending message:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// GET /api/orders/:id/messages
router.get("/orders/:id/messages", async (req, res) => {
  try {
    const orderId = req.params.id;

    const order = await Order.findById(orderId).lean();
    if (!order) return res.status(404).json({ message: "Order not found" });
    res.json({ messages: order.messages || [] });
  } catch (err) {
    console.error("Error fetching messages:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ===================== GET USER INFO =====================
router.get("/profile", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });

    res.json(user);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
// =============== FORGOT PASSWORD ===============
// POST /forgot-password
router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    // Generate a secure token
    const resetToken = crypto.randomBytes(32).toString("hex");
    const hashedToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    // Store hashed token and expiry in DB (expires in 1 hour)
    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    // Debug logging: confirm token and expiry are saved
    const savedUser = await User.findOne({ email });
    console.log("[FORGOT PASSWORD] Email:", email);
    console.log("[FORGOT PASSWORD] Reset token (raw):", resetToken);
    console.log("[FORGOT PASSWORD] Reset token (hashed):", hashedToken);
    console.log("[FORGOT PASSWORD] Saved in DB:", {
      resetPasswordToken: savedUser.resetPasswordToken,
      resetPasswordExpires: savedUser.resetPasswordExpires,
    });

    // Construct reset link
    const resetLink = `${process.env.CLIENT_APP_URL}/reset-password/${resetToken}`;

    // Use Brevo API to send the reset email
    const { sendEmailViaBrevoApi } = require("../services/emailService");
    await sendEmailViaBrevoApi({
      to: user.email,
      subject: "Reset Your MealSection Password",
      html: `
        <div style="background: #fff7f2; min-height: 100vh; padding: 0; margin: 0; font-family: 'Segoe UI', Arial, sans-serif;">
          <div style="max-width: 440px; margin: 56px auto 32px auto; background: #fff; border-radius: 24px; box-shadow: 0 6px 32px rgba(201,26,26,0.10); border: 1.5px solid #f3e5e5; padding: 44px 32px 36px 32px;">
            <div style="display: flex; flex-direction: column; justify-content: center; align-items: center;">
              <img src="https://github.com/Favour-111/my-asset/blob/main/images%20(2).jpeg?raw=true" alt="MealSection Logo" style="width: 150px; " />
              </div>
              <p style="text-align: center; color: #b71c1c; font-size: 13px; font-weight: 500; margin-bottom: 10px;">Food Delivery for Universities</p>
            <h2 style="font-size: 1.22rem;  font-weight: 700; margin-bottom: 12px; text-align: center;">Hi ${
              user.fullName
            } 👋</h2>
            <p style="color: #787878; font-size: 13px; margin-bottom: 24px; text-align: center;">We received a request to reset your MealSection account password. Click the button below to set a new password. If you did not request this, you can safely ignore this email.</p>
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

// POST /reset-password/:token
router.post("/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  if (!newPassword)
    return res.status(400).json({ message: "New password is required" });

  try {
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() }, // token not expired
    });

    if (!user)
      return res.status(400).json({ message: "Invalid or expired token" });

    // Update password
    user.password = await bcrypt.hash(newPassword, 10);

    // Remove reset token & expiry
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    await user.save();

    // Optionally generate JWT
    const jwtToken = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ message: "Password reset successfully", token: jwtToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ===================== GET USER INFO =====================
router.get("/user/:id", async (req, res) => {
  try {
    const { id } = req.params;

    // Find the user by ID and exclude the password field
    const user = await User.findById(id).select("-password");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({
      success: true,
      user,
    });
  } catch (err) {
    console.error("❌ Error fetching user:", err);
    res.status(500).json({ message: "Server error" });
  }
});
// ===================== ADD BALANCE TO USER =====================
// POST /add-balance { userId, amount }
// Removed duplicate /add-balance route. Only robust version remains above.
module.exports = router;
