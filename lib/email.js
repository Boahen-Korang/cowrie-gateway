'use strict';

async function sendOtp(to, otp, businessName) {
  const serviceId  = process.env.EMAILJS_SERVICE_ID;
  const templateId = process.env.EMAILJS_TEMPLATE_ID;
  const publicKey  = process.env.EMAILJS_PUBLIC_KEY;
  const privateKey = process.env.EMAILJS_PRIVATE_KEY;

  if (!serviceId || !templateId || !publicKey || !privateKey) {
    console.log(`[Email] EmailJS not configured — OTP for ${to}: ${otp}`);
    return;
  }

  const res = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      service_id:  serviceId,
      template_id: templateId,
      user_id:     publicKey,
      accessToken: privateKey,
      template_params: {
        to_email:      to,
        otp:           otp,
        business_name: businessName || 'there',
      },
    }),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => res.status);
    console.error(`[Email] EmailJS error for ${to}: ${text}`);
    console.log(`[Email] Fallback OTP for ${to}: ${otp}`);
  }
}

module.exports = { sendOtp };
