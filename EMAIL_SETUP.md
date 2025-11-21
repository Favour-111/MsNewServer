# Email Notification Setup Guide

## Overview

Email notifications are **more reliable** than web push notifications, especially for iOS devices. This system sends emails for:

- 📧 **Vendors**: New order notifications
- 📧 **Customers**: Order status updates (processing, delivered, rider assigned)
- 📧 **Riders**: Delivery assignment notifications

## Gmail Setup (Recommended)

### Step 1: Create or Use Existing Gmail Account

1. Use your business Gmail account (e.g., `notifications@mealsection.com`)
2. Or create a new Gmail account specifically for app notifications

### Step 2: Enable 2-Factor Authentication

1. Go to [Google Account Security](https://myaccount.google.com/security)
2. Click on "2-Step Verification"
3. Follow the prompts to enable 2FA

### Step 3: Generate App Password

1. Go to [App Passwords](https://myaccount.google.com/apppasswords)
2. Select "Mail" as the app
3. Select "Other (Custom name)" as the device
4. Enter "MealSection Notifications" as the name
5. Click "Generate"
6. **Copy the 16-character password** (it will look like: `xxxx xxxx xxxx xxxx`)

### Step 4: Add to .env File

```env
EMAIL_USER=your-email@gmail.com
EMAIL_APP_PASSWORD=xxxxxxxxxxxx
```

**Note:** Paste the app password **without spaces**

### Step 5: Set Application URLs

```env
CLIENT_APP_URL=https://mealsection.com
VENDOR_APP_URL=https://vendor.mealsection.com
RIDER_APP_URL=https://rider.mealsection.com
```

## Alternative Email Providers

### SendGrid (Recommended for Production)

```javascript
// In emailService.js, replace Gmail config with:
const transporter = nodemailer.createTransport({
  host: "smtp.sendgrid.net",
  port: 587,
  auth: {
    user: "apikey",
    pass: process.env.SENDGRID_API_KEY,
  },
});
```

### Mailgun

```javascript
const transporter = nodemailer.createTransport({
  host: "smtp.mailgun.org",
  port: 587,
  auth: {
    user: process.env.MAILGUN_USER,
    pass: process.env.MAILGUN_PASS,
  },
});
```

### AWS SES (Amazon Simple Email Service)

```javascript
const transporter = nodemailer.createTransport({
  host: "email-smtp.us-east-1.amazonaws.com",
  port: 587,
  auth: {
    user: process.env.AWS_SES_USER,
    pass: process.env.AWS_SES_PASS,
  },
});
```

## Testing Email Notifications

### Test Email Sending

```bash
# In Server directory
node -e "
const { sendWelcomeEmail } = require('./services/emailService');
sendWelcomeEmail({
  email: 'test@example.com',
  fullName: 'Test User'
});
"
```

### Check Email Logs

Look for these console messages:

- ✅ `Email sent to vendor vendor@example.com: <message-id>`
- ✅ `Email sent to customer customer@example.com: <message-id>`
- ✅ `Email sent to rider rider@example.com: <message-id>`

## Email Delivery Best Practices

### 1. Verify Domain (Production)

- Add SPF, DKIM, and DMARC records to your domain
- This prevents emails from going to spam

### 2. Use Professional Email Address

- ✅ `notifications@mealsection.com`
- ❌ `personal.email123@gmail.com`

### 3. Monitor Bounce Rates

- Keep bounce rate below 5%
- Remove invalid email addresses

### 4. Unsubscribe Option

- Add unsubscribe link to marketing emails
- Transactional emails (order notifications) don't need this

## Troubleshooting

### Emails Not Sending

1. **Check .env file**: Ensure `EMAIL_USER` and `EMAIL_APP_PASSWORD` are set
2. **Verify App Password**: Make sure you're using App Password, not regular Gmail password
3. **Check Gmail Security**: Ensure "Less secure app access" is OFF (use App Password instead)
4. **Check Logs**: Look for error messages in server console

### Emails Going to Spam

1. **Use Professional Domain**: Instead of Gmail, use your domain email
2. **Verify SPF/DKIM**: Add DNS records for your domain
3. **Avoid Spam Triggers**: Don't use ALL CAPS, excessive exclamation marks!!!
4. **Include Unsubscribe**: For non-transactional emails

### Gmail Daily Limits

- **Free Gmail**: 500 emails/day
- **Google Workspace**: 2,000 emails/day
- **Solution**: Use SendGrid (100 emails/day free) or Mailgun for higher volume

## Email vs Push Notifications

| Feature        | Email                        | Push Notifications           |
| -------------- | ---------------------------- | ---------------------------- |
| iOS Support    | ✅ **Always works**          | ❌ Safari doesn't support    |
| Reliability    | ✅ **99%+ delivery**         | ⚠️ Depends on device/browser |
| Background     | ✅ **Works when app closed** | ❌ Only when app open        |
| User Action    | ✅ Check email anytime       | ⚠️ Must be online            |
| Spam Filtering | ⚠️ Can go to spam            | ✅ Direct delivery           |

## Recommendation

**Use BOTH systems for maximum reliability:**

1. ✅ Email notifications (primary) - works everywhere
2. ✅ Socket.io real-time (when app is open) - instant feedback
3. ⚠️ FCM push notifications (optional) - nice-to-have for Android

This ensures **all users get notifications** regardless of device or browser! 🎉
