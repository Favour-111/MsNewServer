const express = require("express");
const http = require("http");
const dotenv = require("dotenv");
const cors = require("cors");
const connectDB = require("./config/db");
const vendorAuthRoutes = require("./routes/Vendor");
const universityRoutes = require("./routes/universityRoute");
const RiderRoute = require("./routes/RiderRoute");
const riderResetRoutes = require("./routes/riderResetRoutes");
const deliveryFeeRoutes = require("./routes/deliveryFeeRoutes");
const managerRoutes = require("./routes/managerRoute");
const promotionRoutes = require("./routes/promotionRoutes");
const notificationRoutes = require("./routes/notificationRoutes");
const { initSocket } = require("./socket");
const { initializeFirebase } = require("./services/notificationService");
dotenv.config();
const app = express();

connectDB();
initializeFirebase();
app.use(cors({ origin: "*" }));

// Increase body size limits to allow base64 image uploads
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

app.use("/api/users", require("./routes/userRoutes"));
app.use("/api/vendors", vendorAuthRoutes);
app.use("/api/universities", universityRoutes);
app.use("/api/riders", RiderRoute);
app.use("/api/riders", riderResetRoutes);
app.use("/api/delivery", deliveryFeeRoutes);
app.use("/api/managers", managerRoutes);
app.use("/api/promotions", promotionRoutes);
app.use("/api/notifications", notificationRoutes);
app.use("/api/pack-prices", require("./routes/packPriceRoutes"));
app.use(require("./routes/paystackWebhook"));

// Create HTTP server and initialize Socket.IO
const server = http.createServer(app);
initSocket(server);

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
