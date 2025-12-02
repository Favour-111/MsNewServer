const axios = require("axios");

const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const PAYSTACK_VERIFY_URL = process.env.PAYSTACK_VERIFY_URL;

async function verifyPaystackPayment(reference) {
  try {
    const response = await axios.get(PAYSTACK_VERIFY_URL + reference, {
      headers: {
        Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
        "Content-Type": "application/json",
      },
    });
    return response.data;
  } catch (error) {
    throw new Error(
      error.response?.data?.message || "Paystack verification failed"
    );
  }
}

module.exports = { verifyPaystackPayment };
