'use strict';
const FROM = process.env.EMAIL_FROM || 'Cowrie <noreply@cowrie.africa>';

async function sendOtp(to, otp, businessName) {
  if (!process.env.RESEND_API_KEY) {
    console.log(`[Email] No RESEND_API_KEY — OTP for ${to}: ${otp}`);
    return;
  }
  const { Resend } = require('resend');
  const client = new Resend(process.env.RESEND_API_KEY);

  const { error } = await client.emails.send({
    from: FROM,
    to,
    subject: `${otp} is your Cowrie verification code`,
    html: `
<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;background:#ffffff">
  <div style="margin-bottom:28px">
    <span style="font-size:18px;font-weight:800;color:#09071A;letter-spacing:-.02em">Cowrie</span>
  </div>
  <h2 style="font-size:22px;font-weight:800;color:#09071A;margin:0 0 10px">Verify your email address</h2>
  <p style="font-size:15px;color:#564E68;margin:0 0 28px;line-height:1.6">
    Hi ${businessName || 'there'} — use the code below to finish setting up your Cowrie merchant account.
  </p>
  <div style="background:#F3EFF9;border-radius:14px;padding:30px;text-align:center;margin-bottom:28px">
    <p style="font-family:'Courier New',Courier,monospace;font-size:46px;font-weight:900;letter-spacing:.18em;color:#5B2C8F;margin:0;line-height:1">${otp}</p>
    <p style="font-size:12px;color:#7A7388;margin:12px 0 0">Expires in 15 minutes</p>
  </div>
  <p style="font-size:13px;color:#A39CB0;line-height:1.7;margin:0">
    If you didn't create a Cowrie account, you can safely ignore this email. Someone may have mistyped their email address.
  </p>
  <div style="margin-top:32px;padding-top:20px;border-top:1px solid #F0ECE4">
    <p style="font-size:12px;color:#C4BECE;margin:0">© Cowrie · Secure payment infrastructure for Africa</p>
  </div>
</div>`,
  });

  if (error) {
    console.error(`[Email] Resend error for ${to}: ${error.message}`);
    console.log(`[Email] Fallback OTP for ${to}: ${otp}`);
  }
}

module.exports = { sendOtp };
