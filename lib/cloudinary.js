'use strict';
const crypto = require('crypto');

/**
 * Upload a base64 data URL to Cloudinary.
 * Returns the secure HTTPS URL, or null if Cloudinary is not configured.
 * Throws on upload failure.
 */
async function upload(base64DataUrl, folder = 'cowrie-kyc') {
  const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
  const apiKey    = process.env.CLOUDINARY_API_KEY;
  const apiSecret = process.env.CLOUDINARY_API_SECRET;
  if (!cloudName || !apiKey || !apiSecret) return null;

  const timestamp = Math.round(Date.now() / 1000);
  /* Cloudinary signed-upload signature: SHA-1 of sorted params + api_secret */
  const toSign    = `folder=${folder}&timestamp=${timestamp}`;
  const signature = crypto.createHash('sha1').update(toSign + apiSecret).digest('hex');

  const res = await fetch(`https://api.cloudinary.com/v1_1/${cloudName}/auto/upload`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ file: base64DataUrl, api_key: apiKey, timestamp, signature, folder }),
  });

  if (!res.ok) {
    const d = await res.json().catch(() => ({}));
    throw new Error(d.error?.message || `Cloudinary upload failed (HTTP ${res.status})`);
  }

  const data = await res.json();
  return data.secure_url;
}

module.exports = { upload };
