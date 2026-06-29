'use strict';
const nodemailer = require('nodemailer');

const BASE_URL = (process.env.BASE_URL || 'https://cowrie-gateway.onrender.com').replace(/\/$/, '');

function escHtml(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/* ─── Unified send — Resend preferred, Gmail fallback ─── */
async function sendEmail({ to, subject, html, text }) {
  const resendKey = process.env.RESEND_API_KEY;
  const gmailUser = process.env.GMAIL_USER;
  const gmailPass = process.env.GMAIL_APP_PASSWORD;

  if (resendKey) {
    const from = process.env.EMAIL_FROM || 'Cowrie Payments <noreply@cowrie.africa>';
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${resendKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from, to: [to], subject, html, text }),
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      throw new Error(`Resend: ${d.message || res.status}`);
    }
    return;
  }

  if (gmailUser && gmailPass) {
    const t = nodemailer.createTransport({ service: 'gmail', auth: { user: gmailUser, pass: gmailPass } });
    await t.sendMail({ from: `"Cowrie Payments" <${gmailUser}>`, to, subject, html, text });
    return;
  }

  console.log(`[Email] No provider configured — would send "${subject}" to ${to}`);
}

/* ─── OTP ─── */
async function sendOtp(to, otp, businessName) {
  const name = businessName || 'there';
  await sendEmail({
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
        <p style="margin:0 0 8px;font-size:22px;font-weight:700;color:#1a0a2e">Hi ${escHtml(name)},</p>
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

/* ─── KYC approved ─── */
async function sendKycApproved(to, businessName) {
  const name = escHtml(businessName || 'there');
  await sendEmail({
    to,
    subject: '✓ Your Cowrie account has been verified',
    html: `
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f4f4f8;font-family:'Helvetica Neue',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f8;padding:40px 16px">
  <tr><td align="center">
    <table width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
      <tr><td style="background:linear-gradient(135deg,#0f5c3a,#1A9B6E);padding:28px 32px">
        <p style="margin:0;color:rgba(255,255,255,.7);font-size:11px;letter-spacing:.12em;text-transform:uppercase;font-weight:700">Cowrie Payments</p>
      </td></tr>
      <tr><td style="padding:36px 32px 28px">
        <div style="width:56px;height:56px;border-radius:50%;background:#e8f8f1;display:flex;align-items:center;justify-content:center;margin-bottom:22px">
          <span style="font-size:26px">✓</span>
        </div>
        <p style="margin:0 0 8px;font-size:22px;font-weight:700;color:#1a0a2e">Hi ${name},</p>
        <p style="margin:0 0 20px;font-size:15px;color:#666;line-height:1.6">Great news — your <strong>${name}</strong> account on Cowrie has been <strong style="color:#1A9B6E">verified</strong>. You can now accept live payments from your customers.</p>
        <a href="${BASE_URL}/dashboard" style="display:inline-block;background:#1A9B6E;color:#fff;font-weight:700;font-size:14px;padding:13px 28px;border-radius:10px;text-decoration:none;margin-bottom:24px">Go to dashboard →</a>
        <p style="margin:0;font-size:13px;color:#999;line-height:1.6">If you have any questions, reply to this email and we'll help you out.</p>
      </td></tr>
      <tr><td style="padding:20px 32px;border-top:1px solid #f0ecf8">
        <p style="margin:0;font-size:12px;color:#bbb">© Cowrie Payment Gateway</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`,
    text: `Hi ${businessName || 'there'},\n\nYour Cowrie account has been verified! You can now accept live payments.\n\nGo to your dashboard: ${BASE_URL}/dashboard\n\n— Cowrie Payments`,
  });
}

/* ─── KYC rejected ─── */
async function sendKycRejected(to, businessName, reason) {
  const name = escHtml(businessName || 'there');
  const why  = escHtml(reason || 'Your submission did not meet our requirements.');
  await sendEmail({
    to,
    subject: 'Action required: Cowrie account verification',
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
        <p style="margin:0 0 16px;font-size:15px;color:#666;line-height:1.6">We were unable to verify your account at this time. Here is the reason:</p>
        <div style="background:#fff5f5;border-left:4px solid #EF6A4C;border-radius:6px;padding:16px 18px;margin-bottom:24px">
          <p style="margin:0;font-size:14px;color:#333;line-height:1.6">${why}</p>
        </div>
        <p style="margin:0 0 24px;font-size:15px;color:#666;line-height:1.6">Please update your submission and try again from your dashboard.</p>
        <a href="${BASE_URL}/dashboard" style="display:inline-block;background:#5B2C8F;color:#fff;font-weight:700;font-size:14px;padding:13px 28px;border-radius:10px;text-decoration:none;margin-bottom:24px">Resubmit documents →</a>
        <p style="margin:0;font-size:13px;color:#999;line-height:1.6">If you think this is a mistake, reply to this email and we'll look into it.</p>
      </td></tr>
      <tr><td style="padding:20px 32px;border-top:1px solid #f0ecf8">
        <p style="margin:0;font-size:12px;color:#bbb">© Cowrie Payment Gateway</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`,
    text: `Hi ${businessName || 'there'},\n\nWe were unable to verify your account.\n\nReason: ${reason || 'Your submission did not meet our requirements.'}\n\nPlease resubmit your documents: ${BASE_URL}/dashboard\n\n— Cowrie Payments`,
  });
}

module.exports = { sendOtp, sendKycApproved, sendKycRejected };
