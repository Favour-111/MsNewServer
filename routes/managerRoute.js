const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Manager = require("../models/Manager");
const { getIO } = require("../socket");

const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// ✅ SIGN UP route
router.post("/signup", async (req, res) => {
  try {
    const { managerName, university, email, password } = req.body;

    // Check required fields
    if (!managerName || !university || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Check if email already exists
    const existingManager = await Manager.findOne({ email });
    if (existingManager) {
      return res.status(400).json({ message: "Email already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create manager
    const newManager = new Manager({
      managerName,
      university,
      email,
      password: hashedPassword,
    });

    await newManager.save();

    res.status(201).json({
      message: "Manager registered successfully",
      manager: newManager,
    });
    try {
      getIO().emit("managers:signedUp", {
        id: newManager._id,
        university: newManager.university,
      });
    } catch {}
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ LOGIN route
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check required fields
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    // Find manager
    const manager = await Manager.findOne({ email });
    if (!manager) {
      return res.status(404).json({ message: "Manager not found" });
    }

    // Compare passwords
    const isMatch = await bcrypt.compare(password, manager.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: manager._id, email: manager.email, role: manager.role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.status(200).json({
      message: "Login successful",
      token,
      manager: {
        _id: manager._id,
        id: manager._id,
        managerName: manager.managerName,
        email: manager.email,
        role: manager.role,
      },
    });
    try {
      getIO().emit("managers:loggedIn", { id: manager._id });
    } catch {}
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ Get all managers
router.get("/all", async (req, res) => {
  try {
    // Use .lean() for faster query and only select needed fields
    const allManagers = await Manager.find().lean();
    if (allManagers) {
      res.send(allManagers);
    } else {
      res.send({
        status: false,
        message: "Error fetching managers",
      });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ Get single manager by ID (place after /all to avoid route conflicts)
router.get("/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const manager = await Manager.findById(id).select("-password");
    if (!manager) {
      return res.status(404).json({ message: "Manager not found" });
    }
    return res.status(200).json(manager);
  } catch (error) {
    console.error("Get manager error:", error);
    return res.status(500).json({ message: "Server error" });
  }
});

// ✅ Activate a manager
router.patch("/:id/activate", async (req, res) => {
  try {
    const { id } = req.params;
    const manager = await Manager.findByIdAndUpdate(
      id,
      { Active: "true" },
      { new: true }
    );
    if (!manager) return res.status(404).json({ message: "Manager not found" });
    try {
      getIO().emit("managers:updated", {
        id: manager._id,
        Active: manager.Active,
      });
    } catch {}
    return res.json({ message: "Manager activated", manager });
  } catch (err) {
    console.error("Activate manager error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// ✅ Deactivate a manager
router.patch("/:id/deactivate", async (req, res) => {
  try {
    const { id } = req.params;
    const manager = await Manager.findByIdAndUpdate(
      id,
      { Active: "false" },
      { new: true }
    );
    if (!manager) return res.status(404).json({ message: "Manager not found" });
    try {
      getIO().emit("managers:updated", {
        id: manager._id,
        Active: manager.Active,
      });
    } catch {}
    return res.json({ message: "Manager deactivated", manager });
  } catch (err) {
    console.error("Deactivate manager error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
