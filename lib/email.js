'use strict';
const nodemailer = require('nodemailer');

let _transporter = null;

function transporter() {
  if (_transporter) return _transporter;
  const user = process.env.GMAIL_USER;
  const pass = process.env.GMAIL_APP_PASSWORD;
  if (!user || !pass) return null;
  _transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user, pass },
  });
  return _transporter;
}

async function sendOtp(to, otp, businessName) {
  const t = transporter();
  if (!t) {
    console.log(`[Email] Gmail not configured — OTP for ${to}: ${otp}`);
    return;
  }
  const name = businessName || 'there';
  await t.sendMail({
    from: `"Cowrie Payments" <${process.env.GMAIL_USER}>`,
    to,
    subject: 'Your Cowrie verification code',
    html: `
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f4f4f8;font-family:'Helvetica Neue',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f8;padding:40px 16px">
  <tr><td align="center">
    <table width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
      <tr><td style="background:linear-gradient(135deg,#3D1D62,#5B2C8F);padding:28px 32px">
        <p style="margin:0;color:#C9AEFF;font-size:11px;letter-spacing:.12em;text-transform:uppercase;font-weight:700">Cowrie Payments</p>
      </td></tr>
      <tr><td style="padding:36px 32px 28px">
        <p style="margin:0 0 8px;font-size:22px;font-weight:700;color:#1a0a2e">Hi ${name},</p>
        <p style="margin:0 0 28px;font-size:15px;color:#666;line-height:1.6">Here is your verification code. It expires in <strong>15 minutes</strong>.</p>
        <div style="background:#f5f0ff;border-radius:14px;padding:28px;text-align:center;margin-bottom:28px">
          <span style="font-family:'Courier New',monospace;font-size:40px;font-weight:800;letter-spacing:14px;color:#3D1D62">${otp}</span>
        </div>
        <p style="margin:0;font-size:13px;color:#999;line-height:1.6">Do not share this code with anyone. Cowrie staff will never ask for it.</p>
      </td></tr>
      <tr><td style="padding:20px 32px;border-top:1px solid #f0ecf8">
        <p style="margin:0;font-size:12px;color:#bbb">© Cowrie Payment Gateway</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`,
    text: `Hi ${name},\n\nYour Cowrie verification code is:\n\n${otp}\n\nThis code expires in 15 minutes. Do not share it with anyone.\n\n— Cowrie Payments`,
  });
}

module.exports = { sendOtp };
