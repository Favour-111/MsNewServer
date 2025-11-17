# Firebase Cloud Messaging (FCM) Setup Guide

This guide will help you set up Firebase Cloud Messaging for push notifications to Vendors and Riders.

## 📋 Prerequisites

- A Google account
- Access to Firebase Console

## 🔧 Backend Setup (Server)

### Step 1: Create a Firebase Project

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Click **"Add project"** or select an existing project
3. Follow the prompts to create your project (disable Google Analytics if not needed)

### Step 2: Generate Service Account Key

1. In the Firebase Console, click the **gear icon** ⚙️ next to "Project Overview"
2. Select **"Project settings"**
3. Go to the **"Service accounts"** tab
4. Click **"Generate new private key"**
5. Click **"Generate key"** - this will download a JSON file

### Step 3: Configure Environment Variable

1. Open the downloaded JSON file
2. Copy the **entire contents** of the file
3. In your `Server/.env` file, add:

```env
FIREBASE_SERVICE_ACCOUNT='{"type":"service_account","project_id":"your-project-id",...}'
```

**Important:** The entire JSON must be on ONE line as a string value.

**Alternative (More Secure):** Store the JSON file in your server directory and reference it:

```javascript
// In notificationService.js, replace the initialization:
const serviceAccount = require("./firebase-service-account.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
```

### Step 4: Test the Backend

Start your server and check for the Firebase initialization message:

```
✅ Firebase Admin initialized successfully
```

If you see a warning instead, it means the service account is not configured yet (notifications will be disabled until setup).

---

## 📱 Frontend Setup (Vendor & Rider Apps)

### Step 1: Register Your App with Firebase

1. In Firebase Console, go to **Project settings** > **General**
2. Scroll down to **"Your apps"**
3. Click the **Web icon** `</>`
4. Register app with nickname (e.g., "MealSection Vendor App")
5. Copy the **Firebase config object**

### Step 2: Install Firebase SDK

In your Vendor and Rider frontend projects:

```bash
npm install firebase
```

### Step 3: Create Firebase Config File

Create `src/config/firebase.js`:

```javascript
import { initializeApp } from "firebase/app";
import { getMessaging, getToken, onMessage } from "firebase/messaging";

const firebaseConfig = {
  apiKey: "AIzaSy...",
  authDomain: "your-project.firebaseapp.com",
  projectId: "your-project-id",
  storageBucket: "your-project.appspot.com",
  messagingSenderId: "123456789",
  appId: "1:123456789:web:abcdef123456",
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);

// Initialize Cloud Messaging
const messaging = getMessaging(app);

export { messaging, getToken, onMessage };
```

### Step 4: Get VAPID Key

1. In Firebase Console, go to **Project settings** > **Cloud Messaging**
2. Scroll to **"Web configuration"**
3. Under **"Web Push certificates"**, click **"Generate key pair"**
4. Copy the generated key (starts with `B...`)

### Step 5: Request FCM Token on Login

Update your login logic to request notification permission and get FCM token:

```javascript
import { messaging, getToken } from "./config/firebase";

// After successful login
async function registerForPushNotifications() {
  try {
    const permission = await Notification.requestPermission();

    if (permission === "granted") {
      const token = await getToken(messaging, {
        vapidKey: "YOUR_VAPID_KEY_HERE",
      });

      if (token) {
        // Send token to backend during login
        return token;
      }
    }
  } catch (error) {
    console.error("Error getting FCM token:", error);
  }
  return null;
}

// In your login function
const handleLogin = async (email, password) => {
  try {
    const fcmToken = await registerForPushNotifications();

    const response = await axios.post("/api/vendors/login", {
      email,
      password,
      fcmToken, // Include token in login request
    });

    // Handle success...
  } catch (error) {
    // Handle error...
  }
};
```

### Step 6: Create Firebase Messaging Service Worker

Create `public/firebase-messaging-sw.js`:

```javascript
importScripts(
  "https://www.gstatic.com/firebasejs/10.7.0/firebase-app-compat.js"
);
importScripts(
  "https://www.gstatic.com/firebasejs/10.7.0/firebase-messaging-compat.js"
);

firebase.initializeApp({
  apiKey: "AIzaSy...",
  authDomain: "your-project.firebaseapp.com",
  projectId: "your-project-id",
  storageBucket: "your-project.appspot.com",
  messagingSenderId: "123456789",
  appId: "1:123456789:web:abcdef123456",
});

const messaging = firebase.messaging();

// Handle background messages
messaging.onBackgroundMessage((payload) => {
  console.log("Background message received:", payload);

  const notificationTitle = payload.notification.title;
  const notificationOptions = {
    body: payload.notification.body,
    icon: "/logo.png",
    badge: "/badge.png",
    tag: payload.data.orderId,
    requireInteraction: true,
  };

  self.registration.showNotification(notificationTitle, notificationOptions);
});
```

### Step 7: Handle Foreground Messages

In your main App component:

```javascript
import { onMessage } from "./config/firebase";
import { messaging } from "./config/firebase";

useEffect(() => {
  const unsubscribe = onMessage(messaging, (payload) => {
    console.log("Foreground message received:", payload);

    // Show in-app notification or update UI
    alert(`${payload.notification.title}\n${payload.notification.body}`);

    // Or use a toast/notification library
  });

  return () => unsubscribe();
}, []);
```

---

## 🧪 Testing Push Notifications

### Test from Firebase Console

1. Go to **Firebase Console** > **Cloud Messaging**
2. Click **"Send your first message"**
3. Enter notification title and text
4. Click **Next**
5. Select your app
6. Click **Next** and **Review**
7. Click **Publish**

### Test from Your App

1. Login as a vendor or rider (this saves the FCM token)
2. Place an order as a user
3. The vendor should receive a push notification immediately

---

## 🔍 Troubleshooting

### No notification received?

1. Check browser console for errors
2. Verify notification permission is granted
3. Check Firebase Console > Cloud Messaging for any errors
4. Verify service worker is registered (check DevTools > Application > Service Workers)
5. Check backend logs for "Notification sent successfully" message

### "FIREBASE_SERVICE_ACCOUNT not found" warning?

- Add the service account JSON to your `.env` file
- Restart your server after adding the environment variable

### "Invalid registration token" error?

- This means the FCM token is outdated or invalid
- The backend automatically clears invalid tokens from the database
- User needs to log in again to register a new token

### Service worker not found?

- Ensure `firebase-messaging-sw.js` is in your `public/` folder
- Clear browser cache and reload
- Check browser console for service worker registration errors

---

## 📚 Additional Resources

- [Firebase Cloud Messaging Documentation](https://firebase.google.com/docs/cloud-messaging)
- [Firebase Admin SDK Setup](https://firebase.google.com/docs/admin/setup)
- [Web Push Notifications Guide](https://firebase.google.com/docs/cloud-messaging/js/client)

---

## ✅ Implementation Checklist

**Backend:**

- [x] Install `firebase-admin` package
- [x] Create notification service
- [x] Add FCM token fields to Vendor and Rider models
- [x] Update login routes to save FCM tokens
- [x] Integrate notifications in order placement
- [ ] Add Firebase service account to `.env`

**Frontend (Vendor & Rider):**

- [ ] Install `firebase` package
- [ ] Create Firebase config file
- [ ] Add VAPID key
- [ ] Request notification permission on login
- [ ] Send FCM token to backend
- [ ] Create service worker file
- [ ] Handle foreground notifications

**Testing:**

- [ ] Test notification from Firebase Console
- [ ] Test notification from order placement
- [ ] Verify notifications on both Android and iOS (if applicable)
- [ ] Test background and foreground notifications
