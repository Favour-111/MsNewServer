const axios = require("axios");

/**
 * Send email using Brevo transactional email API
 */
async function sendEmailViaBrevoApi({ to, subject, html, from }) {
  try {
    const apiKey = process.env.BREVO_API_KEY;
    const sender = from
      ? { name: from.name || "MealSection", email: from.email }
      : { name: "MealSection", email: process.env.BREVO_SMTP_USER };
    const payload = {
      sender,
      to: Array.isArray(to) ? to.map((email) => ({ email })) : [{ email: to }],
      subject,
      htmlContent: html,
    };
    const response = await axios.post(
      "https://api.brevo.com/v3/smtp/email",
      payload,
      {
        headers: {
          "api-key": apiKey,
          "Content-Type": "application/json",
        },
      }
    );
    console.log(
      `✅ Brevo API email sent to ${to}:`,
      response.data.messageId || response.data
    );
    return response.data;
  } catch (error) {
    console.error(
      `❌ Failed to send Brevo API email to ${to}:`,
      error.response?.data || error.message
    );
    return null;
  }
}
const nodemailer = require("nodemailer");

/**
 * Email notification service - More reliable than FCM, works on all devices including iOS
 */

// Create reusable transporter
let transporter = null;

function getTransporter() {
  if (transporter) return transporter;

  // Use Gmail with App Password (recommended) or other SMTP service
  transporter = nodemailer.createTransport({
    host: process.env.BREVO_SMTP_HOST,
    port: parseInt(process.env.BREVO_SMTP_PORT, 10),
    secure: false, // Brevo uses TLS on port 587
    auth: {
      user: process.env.BREVO_SMTP_USER,
      pass: process.env.BREVO_SMTP_PASS,
    },
  });

  return transporter;
}

/**
 * Send email to vendor about new order
 */
async function sendVendorNewOrderEmail(vendor, orderDetails) {
  try {
    const transporter = getTransporter();

    const mailOptions = {
      from: `"MealSection" <${process.env.EMAIL_USER}>`,
      to: vendor.email,
      subject: "🔔 New Order Received - MealSection",
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #9e0505 0%, #c91a1a 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
            .order-card { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .order-id { font-size: 24px; font-weight: bold; color: #9e0505; margin-bottom: 10px; }
            .detail-row { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #eee; }
            .label { color: #666; }
            .value { font-weight: bold; color: #333; }
            .total { font-size: 15px; color: #10b981; font-weight: bold; }
            .btn { display: inline-block; background: linear-gradient(135deg, #9e0505 0%, #c91a1a 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; margin: 20px 10px; font-weight: bold; }
            .footer { text-align: center; color: #666; font-size: 12px; margin-top: 30px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1 style="margin: 0;">🔔 New Order!</h1>
              <p style="margin: 10px 0 0 0;">You have a new order from MealSection</p>
            </div>
            <div class="content">
              <div class="order-card">
                <div class="order-id">Order #${orderDetails.orderId
                  .slice(-8)
                  .toUpperCase()}</div>
                <div class="detail-row">
                  <span class="label">Customer:</span>
                  <span class="value">${
                    orderDetails.userName || "Customer"
                  }</span>
                </div>
                <div class="detail-row">
                  <span class="label">Items:</span>
                  <span class="value">${orderDetails.itemCount} item(s)</span>
                </div>
                <div class="detail-row">
                  <span class="label">Delivery Address:</span>
                  <span class="value">${orderDetails.address}</span>
                </div>
                <div class="detail-row">
                  <span class="label">Order Total:</span>
                  <span class="total">₦${orderDetails.total?.toLocaleString()}</span>
                </div>
              </div>
              
              <div style="text-align: center;">
                <p><strong>⚠️ Action Required:</strong> Please review and accept/reject this order as soon as possible.</p>
                <a href="${
                  process.env.VENDOR_APP_URL || "https://vendor.mealsection.com"
                }/order" class="btn">View Order Details</a>
              </div>

              <div class="footer">
                <p>This is an automated email from MealSection. Please do not reply directly to this email.</p>
                <p>If you have questions, contact support at mealsection@gmail.com</p>
              </div>
            </div>
          </div>
        </body>
        </html>
      `,
    };

    const info = await transporter.sendMail(mailOptions);
    console.log(`✅ Email sent to vendor ${vendor.email}:`, info.messageId);
    return info;
  } catch (error) {
    console.error(
      `❌ Failed to send email to vendor ${vendor.email}:`,
      error.message
    );
    return null;
  }
}

/**
 * Send email to customer when order status changes
 */
async function sendCustomerOrderUpdateEmail(user, orderDetails) {
  try {
    const transporter = getTransporter();

    let subject = "📦 Order Update - MealSection";
    let title = "Order Update";
    let message = "Your order status has been updated.";
    let emoji = "📦";

    const status = orderDetails.currentStatus?.toLowerCase();
    if (status === "processing") {
      subject = "👨‍🍳 Your Order is Being Prepared!";
      title = "Order Processing";
      message =
        "Your order has been accepted and is being prepared by the vendor.";
      emoji = "👨‍🍳";
    } else if (status === "delivered") {
      subject = "✅ Your Order Has Been Delivered!";
      title = "Order Delivered";
      message = "Your order has been successfully delivered. Enjoy your meal!";
      emoji = "✅";
    } else if (orderDetails.riderAssigned) {
      subject = "🛵 Rider Assigned to Your Order!";
      title = "Rider on the Way";
      message =
        "A rider has been assigned and will pick up your order shortly.";
      emoji = "🛵";
    }

    const mailOptions = {
      from: `"MealSection" <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject,
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
            .status-card { background: white; padding: 25px; border-radius: 8px; margin: 20px 0; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .emoji { font-size: 48px; margin-bottom: 15px; }
            .order-id { font-size: 18px; color: #666; margin-top: 15px; }
            .btn { display: inline-block; background: linear-gradient(135deg, #9e0505 0%, #c91a1a 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; margin: 20px 0; font-weight: bold; }
            .footer { text-align: center; color: #666; font-size: 12px; margin-top: 30px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1 style="margin: 0;">${emoji} ${title}</h1>
            </div>
            <div class="content">
              <div class="status-card">
                <div class="emoji">${emoji}</div>
                <h2 style="margin: 10px 0;">${message}</h2>
                <div class="order-id">Order #${orderDetails.orderId
                  .slice(-8)
                  .toUpperCase()}</div>
              </div>
              
              <div style="text-align: center;">
                <a href="${
                  process.env.CLIENT_APP_URL || "https://mealsection.com"
                }/orders" class="btn">Track Your Order</a>
              </div>

              <div class="footer">
                <p>Thank you for using MealSection!</p>
                <p>Questions? Contact us at mealsection@gmail.com</p>
              </div>
            </div>
          </div>
        </body>
        </html>
      `,
    };

    const info = await transporter.sendMail(mailOptions);
    console.log(`✅ Email sent to customer ${user.email}:`, info.messageId);
    return info;
  } catch (error) {
    console.error(
      `❌ Failed to send email to customer ${user.email}:`,
      error.message
    );
    return null;
  }
}

/**
 * Send email to rider about new delivery assignment
 */
async function sendRiderAssignmentEmail(rider, orderDetails) {
  try {
    const transporter = getTransporter();

    const riderEarnings = (orderDetails.deliveryFee || 0) * 0.5;

    const mailOptions = {
      from: `"MealSection" <${process.env.EMAIL_USER}>`,
      to: rider.email,
      subject: "🛵 New Delivery Assignment - MealSection",
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
            .delivery-card { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .earnings { font-size: 32px; color: #10b981; font-weight: bold; text-align: center; margin: 20px 0; }
            .detail-row { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #eee; }
            .btn { display: inline-block; background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; margin: 20px 0; font-weight: bold; }
            .footer { text-align: center; color: #666; font-size: 12px; margin-top: 30px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1 style="margin: 0;">🛵 New Delivery!</h1>
              <p style="margin: 10px 0 0 0;">You have been assigned a new delivery</p>
            </div>
            <div class="content">
              <div class="delivery-card">
                <h3>Order #${orderDetails.orderId.slice(-8).toUpperCase()}</h3>
                <div class="detail-row">
                  <span>📍 Delivery Address:</span>
                  <strong>${orderDetails.address}</strong>
                </div>
                <div class="detail-row">
                  <span>🏫 University:</span>
                  <strong>${orderDetails.university}</strong>
                </div>
                <div class="earnings">
                  💰 You'll Earn: ₦${riderEarnings.toLocaleString()}
                </div>
              </div>
              
              <div style="text-align: center;">
                <p><strong>🚨 Get Started:</strong> View full delivery details and pickup location</p>
                <a href="${
                  process.env.RIDER_APP_URL || "https://rider.mealsection.com"
                }/order" class="btn">View Delivery Details</a>
              </div>

              <div class="footer">
                <p>Safe travels! Contact support at mealsection@gmail.com if you need help.</p>
              </div>
            </div>
          </div>
        </body>
        </html>
      `,
    };

    const info = await transporter.sendMail(mailOptions);
    console.log(`✅ Email sent to rider ${rider.email}:`, info.messageId);
    return info;
  } catch (error) {
    console.error(
      `❌ Failed to send email to rider ${rider.email}:`,
      error.message
    );
    return null;
  }
}

/**
 * Send email to all riders when vendor accepts an order
 */
async function sendRidersNewOrderAvailableEmail(riders, orderDetails) {
  try {
    const transporter = getTransporter();
    const emailPromises = riders.map(async (rider) => {
      const mailOptions = {
        from: `"MealSection" <${process.env.EMAIL_USER}>`,
        to: rider.email,
        subject: "🚀 New Delivery Available - MealSection",
        html: `
          <!DOCTYPE html>
          <html>
          <head>
            <style>
              body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
              .container { max-width: 600px; margin: 0 auto; padding: 20px; }
              .header { background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
              .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
              .order-card { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
              .earnings { font-size: 28px; color: #10b981; font-weight: bold; text-align: center; margin: 15px 0; }
              .detail-row { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #eee; }
              .btn { display: inline-block; background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; margin: 20px 0; font-weight: bold; }
              .footer { text-align: center; color: #666; font-size: 12px; margin-top: 30px; }
              .highlight { background: #fef3c7; padding: 15px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #f59e0b; }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="header">
                <h1 style="margin: 0;">🚀 New Order Ready!</h1>
                <p style="margin: 10px 0 0 0;">A new delivery is waiting for a rider</p>
              </div>
              <div class="content">
                <div class="order-card">
                  <h3>Order #${orderDetails.orderId
                    .slice(-8)
                    .toUpperCase()}</h3>
                  <div class="detail-row">
                    <span>📍 Delivery Location:</span>
                    <strong>${orderDetails.address}</strong>
                  </div>
                  <div class="detail-row">
                    <span>🏫 University:</span>
                    <strong>${orderDetails.university}</strong>
                  </div>
                  <div class="detail-row">
                    <span>🍽️ From:</span>
                    <strong>${orderDetails.vendorName}</strong>
                  </div>
                  <div class="earnings">
                    💰 Potential Earnings: ₦${(
                      orderDetails.deliveryFee * 0.5
                    ).toLocaleString()}
                  </div>
                </div>
                
                <div class="highlight">
                  <strong>⚡ Quick Action Required!</strong> This order has been accepted by the vendor and is ready for pickup. Accept it now before another rider does!
                </div>
                
                <div style="text-align: center;">
                  <a href="${
                    process.env.RIDER_APP_URL || "https://rider.mealsection.com"
                  }/order" class="btn">View & Accept Order</a>
                </div>

                <div class="footer">
                  <p>First come, first served! Login to your rider dashboard to accept this delivery.</p>
                  <p>Questions? Contact support at mealsection@gmail.com</p>
                </div>
              </div>
            </div>
          </body>
          </html>
        `,
      };

      return transporter.sendMail(mailOptions);
    });

    await Promise.all(emailPromises);
    console.log(`✅ Emails sent to ${riders.length} riders about new order`);
    return true;
  } catch (error) {
    console.error(`❌ Failed to send emails to riders:`, error.message);
    return null;
  }
}

/**
 * Send email to customer when rider starts processing the order
 */
async function sendCustomerRiderPickedOrderEmail(
  user,
  orderDetails,
  riderName
) {
  try {
    const transporter = getTransporter();

    const mailOptions = {
      from: `"MealSection" <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: "🛵 Your Order Is On The Way! - MealSection",
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
            .status-card { background: white; padding: 25px; border-radius: 8px; margin: 20px 0; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .emoji { font-size: 64px; margin-bottom: 15px; }
            .order-id { font-size: 18px; color: #666; margin-top: 15px; font-family: monospace; background: #f3f4f6; padding: 10px; border-radius: 8px; }
            .timeline { margin: 25px 0; }
            .timeline-item { display: flex; align-items: center; margin: 15px 0; }
            .timeline-icon { width: 30px; height: 30px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-right: 15px; font-size: 14px; }
            .completed { background: #10b981; color: white; }
            .active { background: #f59e0b; color: white; animation: pulse 2s infinite; }
            .pending { background: #e5e7eb; color: #9ca3af; }
            @keyframes pulse {
              0%, 100% { opacity: 1; }
              50% { opacity: 0.5; }
            }
            .btn { display: inline-block; background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; margin: 20px 0; font-weight: bold; }
            .footer { text-align: center; color: #666; font-size: 12px; margin-top: 30px; }
            .info-box { background: #eff6ff; border-left: 4px solid #3b82f6; padding: 15px; border-radius: 8px; margin: 20px 0; }
          </style>
          </head>
          <body>
            <div class="container">
              <div class="header">
                <h1 style="margin: 0;">🛵 Your Order Is On The Way!</h1>
                <p style="margin: 10px 0 0 0;">Your rider has started the delivery</p>
              </div>
              <div class="content">
                <div class="status-card">
                  <div class="emoji">🛵</div>
                  <h2 style="margin: 10px 0; color: #f59e0b;">Out for Delivery!</h2>
                  <p style="color: #666; margin: 10px 0;">Your delicious meal is on its way to you</p>
                  <div class="order-id">Order #${orderDetails.orderId
                    .slice(-8)
                    .toUpperCase()}</div>
                </div>

                <div class="info-box">
                  <strong>📍 Delivery Address:</strong> ${orderDetails.address}
                </div>
                
                <div class="timeline">
                  <div class="timeline-item">
                    <div class="timeline-icon completed">✓</div>
                    <div>
                      <strong>Order Placed</strong>
                      <div style="font-size: 12px; color: #666;">Your order was received</div>
                    </div>
                  </div>
                  <div class="timeline-item">
                    <div class="timeline-icon completed">✓</div>
                    <div>
                      <strong>Preparing Food</strong>
                      <div style="font-size: 12px; color: #666;">Vendor accepted and prepared your meal</div>
                    </div>
                  </div>
                  <div class="timeline-item">
                    <div class="timeline-icon active">🛵</div>
                    <div>
                      <strong style="color: #f59e0b;">Out for Delivery</strong>
                      <div style="font-size: 12px; color: #f59e0b;">Rider is bringing your order now!</div>
                    </div>
                  </div>
                  <div class="timeline-item">
                    <div class="timeline-icon pending">○</div>
                    <div style="color: #9ca3af;">
                      <strong>Delivered</strong>
                      <div style="font-size: 12px;">Your meal will arrive soon</div>
                    </div>
                  </div>
                </div>

                <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0; text-align: center;">
                  <p style="margin: 0; color: #666;">📞 <strong>Pro Tip:</strong> Keep your phone nearby in case the rider needs to contact you!</p>
                </div>
                
                <div style="text-align: center;">
                  <a href="${
                    process.env.CLIENT_APP_URL || "https://mealsection.com"
                  }/orders" class="btn">Track Your Order</a>
                </div>

                <div class="footer">
                  <p>Thank you for using MealSection! Your meal will arrive shortly.</p>
                  <p>Questions? Contact us at mealsection@gmail.com</p>
                </div>
              </div>
            </div>
          </body>
          </html>
      `,
    };

    const info = await transporter.sendMail(mailOptions);
    console.log(
      `✅ Rider pickup email sent to customer ${user.email}:`,
      info.messageId
    );
    return info;
  } catch (error) {
    console.error(
      `❌ Failed to send rider pickup email to customer ${user.email}:`,
      error.message
    );
    return null;
  }
}

/**
 * Send welcome email to new user
 */
async function sendWelcomeEmail(user) {
  try {
    const transporter = getTransporter();

    const mailOptions = {
      from: `"MealSection" <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: "🎉 Welcome to MealSection!",
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #9e0505 0%, #c91a1a 100%); color: white; padding: 40px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
            .welcome-message { background: white; padding: 25px; border-radius: 8px; margin: 20px 0; }
            .btn { display: inline-block; background: linear-gradient(135deg, #9e0505 0%, #c91a1a 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; margin: 20px 0; font-weight: bold; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1 style="margin: 0;">🎉 Welcome to MealSection!</h1>
              <p style="margin: 10px 0 0 0;">Your campus food delivery is ready</p>
            </div>
            <div class="content">
              <div class="welcome-message">
                <h2>Hi ${user.fullName || user.email}! 👋</h2>
                <p>Welcome to MealSection - your one-stop solution for delicious campus meals delivered fast!</p>
                <p><strong>You're all set!</strong> You can now:</p>
                <ul>
                  <li>🍔 Browse menus from your favorite campus vendors</li>
                  <li>📦 Create custom meal packs</li>
                  <li>🚚 Track your deliveries in real-time</li>
                  <li>💰 Manage your wallet and payments</li>
                </ul>
              </div>
              
              <div style="text-align: center;">
                <a href="${
                  process.env.CLIENT_APP_URL || "https://mealsection.com"
                }/vendors" class="btn">Start Ordering Now!</a>
              </div>

              <div style="text-align: center; color: #666; font-size: 12px; margin-top: 30px;">
                <p>Need help? Contact us at mealsection@gmail.com</p>
              </div>
            </div>
          </div>
        </body>
        </html>
      `,
    };

    const info = await transporter.sendMail(mailOptions);
    console.log(`✅ Welcome email sent to ${user.email}:`, info.messageId);
    return info;
  } catch (error) {
    console.error(
      `❌ Failed to send welcome email to ${user.email}:`,
      error.message
    );
    return null;
  }
}

/**
 * Send email to customer when order is rejected and refunded
 */
async function sendCustomerOrderRejectedEmail(user, orderDetails) {
  try {
    const transporter = getTransporter();

    const mailOptions = {
      from: `"MealSection" <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: "❌ Order Declined - Refund Processed - MealSection",
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
            .status-card { background: white; padding: 25px; border-radius: 8px; margin: 20px 0; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .emoji { font-size: 64px; margin-bottom: 15px; }
            .order-id { font-size: 18px; color: #666; margin-top: 15px; font-family: monospace; background: #f3f4f6; padding: 10px; border-radius: 8px; }
            .refund-box { background: #d1fae5; border: 2px solid #10b981; border-radius: 8px; padding: 20px; margin: 20px 0; text-align: center; }
            .refund-amount { font-size: 36px; color: #10b981; font-weight: bold; margin: 10px 0; }
            .info-box { background: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; border-radius: 8px; margin: 20px 0; }
            .btn { display: inline-block; background: linear-gradient(135deg, #9e0505 0%, #c91a1a 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; margin: 20px 0; font-weight: bold; }
            .footer { text-align: center; color: #666; font-size: 12px; margin-top: 30px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1 style="margin: 0;">❌ Order Declined</h1>
              <p style="margin: 10px 0 0 0;">We're sorry, your order couldn't be completed</p>
            </div>
            <div class="content">
              <div class="status-card">
                <div class="emoji">😔</div>
                <h2 style="margin: 10px 0; color: #ef4444;">Order Could Not Be Processed</h2>
                <p style="color: #666; margin: 10px 0;">Unfortunately, ${
                  orderDetails.vendorName || "the vendor"
                } was unable to accept your order at this time.</p>
                <div class="order-id">Order #${orderDetails.orderId
                  .slice(-8)
                  .toUpperCase()}</div>
              </div>

              <div class="refund-box">
                <div style="font-size: 20px; color: #059669; margin-bottom: 10px;">✅ Full Refund Processed</div>
                <div class="refund-amount">₦${orderDetails.refundAmount.toLocaleString()}</div>
                <p style="color: #059669; margin: 10px 0; font-weight: 600;">has been credited back to your wallet</p>
              </div>

              <div class="info-box">
                <strong>💡 What happens next?</strong>
                <ul style="margin: 10px 0; padding-left: 20px;">
                  <li>Your full payment has been refunded instantly</li>
                  <li>You can use your balance to order from other vendors</li>
                  <li>The refund includes all fees (subtotal + service fee + delivery fee)</li>
                </ul>
              </div>

              <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0; text-align: center;">
                <p style="margin: 0; color: #666;"><strong>We're sorry for the inconvenience!</strong></p>
                <p style="margin: 10px 0; color: #666;">This can happen when vendors are busy or items are unavailable. Please try ordering again from another vendor.</p>
              </div>
              
              <div style="text-align: center;">
                <a href="${
                  process.env.CLIENT_APP_URL || "https://mealsection.com"
                }/vendors" class="btn">Browse Other Vendors</a>
              </div>

              <div class="footer">
                <p>If you have any questions about this refund, please contact us.</p>
                <p>Email: mealsection@gmail.com</p>
              </div>
            </div>
          </div>
        </body>
        </html>
      `,
    };

    const info = await transporter.sendMail(mailOptions);
    console.log(
      `✅ Order rejection & refund email sent to ${user.email}:`,
      info.messageId
    );
    return info;
  } catch (error) {
    console.error(
      `❌ Failed to send rejection email to ${user.email}:`,
      error.message
    );
    return null;
  }
}

/**
 * Generic sendEmail function for admin alerts and notifications
 */
async function sendEmail({ to, subject, text, html }) {
  /**
   * Generic email sender for custom emails (e.g., forgot password)
   */
  async function sendEmail({ to, subject, html, from }) {
    try {
      const transporter = getTransporter();
      const mailOptions = {
        from: from || `"MealSection" <${process.env.BREVO_SMTP_USER}>`,
        to,
        subject,
        html,
      };
      const info = await transporter.sendMail(mailOptions);
      console.log(`✅ Email sent to ${to}:`, info.messageId);
      return info;
    } catch (error) {
      console.error(`❌ Failed to send email to ${to}:`, error.message);
      return null;
    }
  }
  try {
    const transporter = getTransporter();
    const mailOptions = {
      from: `"MealSection" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      text,
      html,
    };
    const info = await transporter.sendMail(mailOptions);
    console.log(`✅ Generic email sent to ${to}:`, info.messageId);
    return info;
  } catch (error) {
    console.error(`❌ Failed to send generic email to ${to}:`, error.message);
    return null;
  }
}

module.exports = {
  sendVendorNewOrderEmail,
  sendCustomerOrderUpdateEmail,
  sendRiderAssignmentEmail,
  sendWelcomeEmail,
  sendRidersNewOrderAvailableEmail,
  sendCustomerRiderPickedOrderEmail,
  sendCustomerOrderRejectedEmail,
  sendEmailViaBrevoApi,
};
