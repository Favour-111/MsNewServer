# Quick Start: Getting Your Firebase Credentials

## 🎯 What You Need

There are **2 main pieces of information** you need to get from Firebase:

### 1. **Backend (Server)** - Service Account JSON

### 2. **Frontend (Vendor/Rider Apps)** - Firebase Config + VAPID Key

---

## 📝 Step-by-Step: Getting Backend Credentials

### Go to Firebase Console

1. Visit: https://console.firebase.google.com/
2. **Sign in** with your Google account
3. Click **"Add project"** (or select existing project)
4. Enter project name: `MealSection` (or any name you prefer)
5. Disable Google Analytics (optional) → Click **Continue**
6. Wait for project creation → Click **Continue**

### Get Service Account Key (for Backend)

1. Click the **⚙️ gear icon** next to "Project Overview" (top left)
2. Select **"Project settings"**
3. Go to **"Service accounts"** tab (at the top)
4. Click the button: **"Generate new private key"**
5. A dialog appears → Click **"Generate key"**
6. A JSON file downloads automatically (e.g., `mealsection-abc123-firebase-adminsdk-xyz.json`)

### Add to Your .env File

1. Open the downloaded JSON file with any text editor
2. Copy **the entire content** (it should look like this):

```json
{
  "type": "service_account",
  "project_id": "mealsection-abc123",
  "private_key_id": "1234567890abcdef...",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQ...",
  "client_email": "firebase-adminsdk-xyz@mealsection.iam.gserviceaccount.com",
  "client_id": "123456789012345678",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://..."
}
```

3. Open `Server/.env` file
4. Add this line (replace with your actual JSON content):

```env
FIREBASE_SERVICE_ACCOUNT='{"type":"service_account","project_id":"mealsection-abc123","private_key_id":"...","private_key":"-----BEGIN PRIVATE KEY-----\\nMIIEvQ...","client_email":"firebase-adminsdk-xyz@mealsection.iam.gserviceaccount.com","client_id":"123456789012345678","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_x509_cert_url":"https://..."}'
```

⚠️ **Important Notes:**

- Put the entire JSON on **ONE line**
- Wrap it in **single quotes** `'...'`
- Replace `\n` with `\\n` in the private_key (or just copy as-is)
- Don't add any line breaks inside the JSON string

5. Save the `.env` file
6. Restart your server

✅ You should see: `✅ Firebase Admin initialized successfully`

---

## 📱 Step-by-Step: Getting Frontend Credentials

### Register Your Web App

1. In Firebase Console, click **⚙️ gear icon** → **"Project settings"**
2. Scroll down to **"Your apps"** section
3. Click the **Web icon** `</>`
4. Enter app nickname: `MealSection Vendor` (or `MealSection Rider`)
5. ✅ Check **"Also set up Firebase Hosting"** (optional)
6. Click **"Register app"**

### Copy Firebase Config

You'll see a code snippet like this:

```javascript
const firebaseConfig = {
  apiKey: "AIzaSyBXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  authDomain: "mealsection-abc123.firebaseapp.com",
  projectId: "mealsection-abc123",
  storageBucket: "mealsection-abc123.appspot.com",
  messagingSenderId: "123456789012",
  appId: "1:123456789012:web:abcdef1234567890",
};
```

📋 **Save this** - you'll need it for your Vendor and Rider frontend apps.

Click **"Continue to console"**

### Get VAPID Key (Web Push Certificate)

1. Still in **Project settings** → Go to **"Cloud Messaging"** tab
2. Scroll down to **"Web configuration"** section
3. Under **"Web Push certificates"**, click **"Generate key pair"**
4. A key appears (starts with `B...`) - example:

```
BMPxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

📋 **Copy this key** - you'll use it when requesting notification permission.

---

## 🔧 What Goes Where?

### **Backend (Server/.env)**

```env
# Your existing variables...
PORT=5000
MONGO_URI=mongodb://...
JWT_SECRET=supersecretkey
EMAIL=your-email@gmail.com
EMAIL_PASSWORD=your-app-password

# ADD THIS (Service Account JSON on one line)
FIREBASE_SERVICE_ACCOUNT='{"type":"service_account","project_id":"mealsection-abc123",...}'
```

### **Frontend (Vendor/src/config/firebase.js)**

```javascript
import { initializeApp } from "firebase/app";
import { getMessaging, getToken, onMessage } from "firebase/messaging";

const firebaseConfig = {
  apiKey: "AIzaSyBXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  authDomain: "mealsection-abc123.firebaseapp.com",
  projectId: "mealsection-abc123",
  storageBucket: "mealsection-abc123.appspot.com",
  messagingSenderId: "123456789012",
  appId: "1:123456789012:web:abcdef1234567890",
};

const app = initializeApp(firebaseConfig);
const messaging = getMessaging(app);

export { messaging, getToken, onMessage };
```

### **Frontend (Vendor/src/login.js or similar)**

```javascript
const VAPID_KEY =
  "BMPxXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

const token = await getToken(messaging, { vapidKey: VAPID_KEY });
```

---

## ✅ Verification Checklist

**Backend:**

- [ ] Created Firebase project
- [ ] Downloaded service account JSON file
- [ ] Added JSON to `Server/.env` as `FIREBASE_SERVICE_ACCOUNT`
- [ ] Restarted server
- [ ] See "✅ Firebase Admin initialized successfully" in console

**Frontend:**

- [ ] Registered web app in Firebase Console
- [ ] Copied Firebase config object
- [ ] Generated and copied VAPID key
- [ ] Will create `firebase.js` config file (next step)

---

## 🆘 Need Help?

**Can't find Service Accounts tab?**

- Make sure you're in "Project settings" (⚙️ icon)
- It's at the top: Overview | General | Service accounts | ...

**Can't find Cloud Messaging tab?**

- Go to Project settings → Look for tabs at top
- Should see: General | Service accounts | Cloud Messaging | ...

**JSON file won't fit on one line?**

- Just copy the entire content as-is and wrap in single quotes
- Or use online JSON minifier: https://www.cleancss.com/json-minify/

**Still stuck?**

- Send me a screenshot of where you're stuck
- Or share the error message you're seeing
