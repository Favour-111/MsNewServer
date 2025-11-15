const express = require("express");
const http = require("http");
const dotenv = require("dotenv");
const cors = require("cors");
const connectDB = require("./config/db");
const vendorAuthRoutes = require("./routes/Vendor");
const universityRoutes = require("./routes/universityRoute");
const RiderRoute = require("./routes/RiderRoute");
const deliveryFeeRoutes = require("./routes/deliveryFeeRoutes");
const managerRoutes = require("./routes/managerRoute");
const { initSocket } = require("./socket");
dotenv.config();
const app = express();

connectDB();
app.use(cors({ origin: "*" }));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use("/api/users", require("./routes/userRoutes"));
app.use("/api/vendors", vendorAuthRoutes);
app.use("/api/universities", universityRoutes);
app.use("/api/riders", RiderRoute);
app.use("/api/delivery", deliveryFeeRoutes);
app.use("/api/managers", managerRoutes);

// Create HTTP server and initialize Socket.IO
const server = http.createServer(app);
initSocket(server);

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
