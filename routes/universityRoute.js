const express = require("express");
const University = require("../models/University.js");

const router = express.Router();
router.post("/addUni", async (req, res) => {
  try {
    const { name } = req.body;

    if (!name) {
      return res.status(400).json({ message: "University name is required." });
    }

    const existing = await University.findOne({ name }); // ✅ works if model is correct
    if (existing) {
      return res.status(400).json({ message: "University already exists." });
    }

    const university = await University.create({ name });
    res.status(201).json({
      message: "University added successfully.",
      university,
    });
  } catch (err) {
    console.error("Error adding university:", err.message);
    res.status(500).json({ message: "Server error" });
  }
});

router.get("/", async (req, res) => {
  try {
    // Use .lean() for faster query and only select needed fields
    const universities = await University.find().sort({ name: 1 }).lean();
    res.json({ count: universities.length, universities });
  } catch (err) {
    console.error("Error fetching universities:", err.message);
    res.status(500).json({ message: "Server error" });
  }
});
module.exports = router;
