const { Server } = require("socket.io");

let ioRef = null;

function initSocket(server) {
  ioRef = new Server(server, {
    cors: {
      origin: process.env.CLIENT_ORIGINS?.split(",") || ["*"],
      methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
      credentials: true,
    },
    // ✅ MEMORY OPTIMIZATION for 512MB RAM - reduce connection overhead
    maxHttpBufferSize: 1e6, // 1MB max message size
    transports: ["websocket", "polling"], // Prefer websocket over polling
    reconnectionDelay: 1000,
    reconnectionDelayMax: 5000,
    reconnectionAttempts: 5,
  });

  ioRef.on("connection", (socket) => {
    console.log(`✅ Client connected: ${socket.id}`);

    // ✅ Join room based on vendor/manager/rider role
    socket.on("join", (data) => {
      const { role, university, userId, storeId } = data || {};

      // Join role-based room (e.g., "vendor:store123", "manager:oxford", "rider:lmu")
      if (role === "vendor" && storeId) {
        socket.join(`vendor:${storeId}`);
        console.log(`Vendor joined room: vendor:${storeId}`);
      } else if (role === "manager" && university) {
        socket.join(`manager:${university}`);
        console.log(`Manager joined room: manager:${university}`);
      } else if (role === "rider" && university) {
        socket.join(`rider:${university}`);
        console.log(`Rider joined room: rider:${university}`);
      }

      // Also join a general order room for real-time updates
      if (data && data.room) {
        socket.join(data.room);
        console.log(`Socket joined room: ${data.room}`);
      }
    });

    socket.on("disconnect", () => {
      console.log(`❌ Client disconnected: ${socket.id}`);
    });

    // ✅ Handle errors
    socket.on("error", (error) => {
      console.error(`Socket error for ${socket.id}:`, error);
    });
  });

  return ioRef;
}

function getIO() {
  if (!ioRef) throw new Error("Socket.io not initialized");
  return ioRef;
}

// ✅ Helper function to emit to specific vendors
function notifyVendor(vendorId, event, data) {
  if (ioRef) {
    ioRef.to(`vendor:${vendorId}`).emit(event, data);
    console.log(`📤 Emitted to vendor ${vendorId}:`, event);
  }
}

// ✅ Helper function to emit to specific managers
function notifyManager(university, event, data) {
  if (ioRef) {
    ioRef.to(`manager:${university}`).emit(event, data);
    console.log(`📤 Emitted to manager (${university}):`, event);
  }
}

// ✅ Helper function to emit to specific riders
function notifyRiders(university, event, data) {
  if (ioRef) {
    ioRef.to(`rider:${university}`).emit(event, data);
    console.log(`📤 Emitted to riders (${university}):`, event);
  }
}

// ✅ Helper function to broadcast to all connected clients
function broadcastToAll(event, data) {
  if (ioRef) {
    ioRef.emit(event, data);
    console.log(`📢 Broadcast to all:`, event);
  }
}

module.exports = {
  initSocket,
  getIO,
  notifyVendor,
  notifyManager,
  notifyRiders,
  broadcastToAll,
};
