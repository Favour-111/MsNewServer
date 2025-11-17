const admin = require("firebase-admin");

// Initialize Firebase Admin SDK
let firebaseInitialized = false;

function initializeFirebase() {
  if (firebaseInitialized) return;

  try {
    // Check if service account exists
    if (process.env.FIREBASE_SERVICE_ACCOUNT) {
      const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
      });
      firebaseInitialized = true;
      console.log("✅ Firebase Admin initialized successfully");
    } else {
      console.warn(
        "⚠️ FIREBASE_SERVICE_ACCOUNT not found in .env - Push notifications disabled"
      );
    }
  } catch (error) {
    console.error("❌ Firebase initialization error:", error.message);
  }
}

// Send notification to a single device
async function sendNotificationToDevice(token, title, body, data = {}) {
  if (!firebaseInitialized) {
    console.log("Firebase not initialized, skipping notification");
    return null;
  }

  try {
    const message = {
      notification: {
        title,
        body,
      },
      data,
      token,
      android: {
        priority: "high",
        notification: {
          sound: "default",
          channelId: "orders",
        },
      },
      apns: {
        payload: {
          aps: {
            sound: "default",
            badge: 1,
          },
        },
      },
    };

    const response = await admin.messaging().send(message);
    console.log("✅ Notification sent successfully:", response);
    return response;
  } catch (error) {
    console.error("❌ Error sending notification:", error.message);
    // If token is invalid, return error for cleanup
    if (
      error.code === "messaging/invalid-registration-token" ||
      error.code === "messaging/registration-token-not-registered"
    ) {
      return { error: "INVALID_TOKEN" };
    }
    return null;
  }
}

// Send notification to multiple devices
async function sendNotificationToMultipleDevices(
  tokens,
  title,
  body,
  data = {}
) {
  if (!firebaseInitialized || !tokens || tokens.length === 0) {
    return null;
  }

  try {
    const message = {
      notification: {
        title,
        body,
      },
      data,
      tokens: tokens.filter(Boolean), // Remove null/undefined tokens
      android: {
        priority: "high",
        notification: {
          sound: "default",
          channelId: "orders",
        },
      },
      apns: {
        payload: {
          aps: {
            sound: "default",
            badge: 1,
          },
        },
      },
    };

    const response = await admin.messaging().sendEachForMulticast(message);
    console.log(
      `✅ Notifications sent: ${response.successCount} success, ${response.failureCount} failed`
    );
    return response;
  } catch (error) {
    console.error("❌ Error sending multiple notifications:", error.message);
    return null;
  }
}

// Send notification to vendor about new order
async function notifyVendorNewOrder(vendor, orderDetails) {
  if (!vendor.fcmToken) {
    console.log(`Vendor ${vendor.storeName} has no FCM token`);
    return;
  }

  const title = "🔔 New Order Received!";
  const body = `You have a new order for ${orderDetails.itemCount} item(s) - ₦${orderDetails.total}`;
  const data = {
    type: "NEW_ORDER",
    orderId: orderDetails.orderId,
    storeName: vendor.storeName,
    timestamp: new Date().toISOString(),
  };

  const result = await sendNotificationToDevice(
    vendor.fcmToken,
    title,
    body,
    data
  );

  // If token is invalid, clear it from database
  if (result?.error === "INVALID_TOKEN") {
    const Vendor = require("../models/Vendor");
    await Vendor.findByIdAndUpdate(vendor._id, { fcmToken: null });
    console.log(`Cleared invalid FCM token for vendor: ${vendor.storeName}`);
  }
}

// Send notification to rider about assigned order
async function notifyRiderNewAssignment(rider, orderDetails) {
  if (!rider.fcmToken) {
    console.log(`Rider ${rider.userName} has no FCM token`);
    return;
  }

  const title = "🛵 New Delivery Assignment!";
  const body = `You have been assigned a new delivery to ${orderDetails.address}`;
  const data = {
    type: "NEW_ASSIGNMENT",
    orderId: orderDetails.orderId,
    riderName: rider.userName,
    timestamp: new Date().toISOString(),
  };

  const result = await sendNotificationToDevice(
    rider.fcmToken,
    title,
    body,
    data
  );

  // If token is invalid, clear it from database
  if (result?.error === "INVALID_TOKEN") {
    const Rider = require("../models/Rider");
    await Rider.findByIdAndUpdate(rider._id, { fcmToken: null });
    console.log(`Cleared invalid FCM token for rider: ${rider.userName}`);
  }
}

// Send notification to all vendors in a university about new order
async function notifyAllVendorsInUniversity(university, orderDetails) {
  const Vendor = require("../models/Vendor");
  const vendors = await Vendor.find({
    university,
    fcmToken: { $exists: true, $ne: null },
  });

  if (vendors.length === 0) {
    console.log(`No vendors with FCM tokens in ${university}`);
    return;
  }

  const tokens = vendors.map((v) => v.fcmToken);
  const title = "🔔 New Order Alert!";
  const body = `New order placed in ${university} - Check your dashboard`;
  const data = {
    type: "NEW_ORDER_ALERT",
    university,
    timestamp: new Date().toISOString(),
  };

  await sendNotificationToMultipleDevices(tokens, title, body, data);
}

// Send notification to all riders about accepted order (available for pickup)
async function notifyAllRidersOrderAccepted(university, orderDetails) {
  const Rider = require("../models/Rider");
  const riders = await Rider.find({
    university,
    fcmToken: { $exists: true, $ne: null },
  });

  if (riders.length === 0) {
    console.log(`No riders with FCM tokens in ${university}`);
    return;
  }

  const tokens = riders.map((r) => r.fcmToken);
  const title = "🛵 New Delivery Available!";
  const body = `Order #${orderDetails.orderId.slice(-6)} accepted by ${
    orderDetails.vendorName
  } - Ready for pickup`;
  const data = {
    type: "ORDER_ACCEPTED",
    orderId: orderDetails.orderId,
    vendorName: orderDetails.vendorName,
    university,
    address: orderDetails.address,
    timestamp: new Date().toISOString(),
  };

  const result = await sendNotificationToMultipleDevices(
    tokens,
    title,
    body,
    data
  );
  console.log(
    `Notified ${riders.length} riders about accepted order in ${university}`
  );
  return result;
}

// Send notification to all riders about rejected order
async function notifyAllRidersOrderRejected(university, orderDetails) {
  const Rider = require("../models/Rider");
  const riders = await Rider.find({
    university,
    fcmToken: { $exists: true, $ne: null },
  });

  if (riders.length === 0) {
    console.log(`No riders with FCM tokens in ${university}`);
    return;
  }

  const tokens = riders.map((r) => r.fcmToken);
  const title = "❌ Order Rejected";
  const body = `Order #${orderDetails.orderId.slice(-6)} was rejected by ${
    orderDetails.vendorName
  }`;
  const data = {
    type: "ORDER_REJECTED",
    orderId: orderDetails.orderId,
    vendorName: orderDetails.vendorName,
    university,
    timestamp: new Date().toISOString(),
  };

  const result = await sendNotificationToMultipleDevices(
    tokens,
    title,
    body,
    data
  );
  console.log(
    `Notified ${riders.length} riders about rejected order in ${university}`
  );
  return result;
}

// Send notification to user when order is picked up by rider
async function notifyUserOrderPickedUp(user, orderDetails) {
  if (!user.fcmToken) {
    console.log(`User ${user.fullName} has no FCM token`);
    return;
  }

  const title = "🛵 Your Order is On the Way!";
  const body = `Your order has been picked up by ${orderDetails.riderName}. It will arrive soon!`;
  const data = {
    type: "ORDER_PICKED_UP",
    orderId: orderDetails.orderId,
    riderName: orderDetails.riderName,
    timestamp: new Date().toISOString(),
  };

  const result = await sendNotificationToDevice(
    user.fcmToken,
    title,
    body,
    data
  );

  // If token is invalid, clear it from database
  if (result?.error === "INVALID_TOKEN") {
    const User = require("../models/User");
    await User.findByIdAndUpdate(user._id, { fcmToken: null });
    console.log(`Cleared invalid FCM token for user: ${user.fullName}`);
  }
}

module.exports = {
  initializeFirebase,
  sendNotificationToDevice,
  sendNotificationToMultipleDevices,
  notifyVendorNewOrder,
  notifyRiderNewAssignment,
  notifyAllVendorsInUniversity,
  notifyAllRidersOrderAccepted,
  notifyAllRidersOrderRejected,
  notifyUserOrderPickedUp,
};
