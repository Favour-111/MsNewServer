const express = require("express");
const router = express.Router();
const { sendNotificationToDevice } = require("../services/notificationService");

// POST /api/notifications/test
// Body: { token: string, title?: string, body?: string, data?: object }
router.post("/test", async (req, res) => {
  try {
    const { token, title, body, data } = req.body || {};
    if (!token) {
      return res.status(400).json({ error: "token is required" });
    }

    const response = await sendNotificationToDevice(
      token,
      title || "MealSection Test",
      body || "This is a test push notification",
      data || { type: "TEST", timestamp: new Date().toISOString() }
    );

    if (response?.error === "INVALID_TOKEN") {
      return res.status(400).json({ error: "INVALID_TOKEN" });
    }

    return res.json({ ok: true, id: response });
  } catch (error) {
    return res.status(500).json({ error: error.message || "send failed" });
  }
});

module.exports = router;
