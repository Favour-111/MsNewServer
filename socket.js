const { Server } = require("socket.io");

let ioRef = null;

function initSocket(server) {
  ioRef = new Server(server, {
    cors: {
      origin: process.env.CLIENT_ORIGINS?.split(",") || ["*"],
      methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
      credentials: true,
    },
  });

  ioRef.on("connection", (socket) => {
    // Optional: accept room joins for roles or universities
    socket.on("join", (room) => {
      if (room) socket.join(room);
    });

    socket.on("disconnect", () => {
      // cleanup if needed
    });
  });

  return ioRef;
}

function getIO() {
  if (!ioRef) throw new Error("Socket.io not initialized");
  return ioRef;
}

module.exports = { initSocket, getIO };
