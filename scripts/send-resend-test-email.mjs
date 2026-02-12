/**
 * Send a test email via Resend using RESEND_API_KEY from .env.
 * Run from project root: node scripts/send-resend-test-email.mjs
 *
 * Ensure .env contains: RESEND_API_KEY=re_your_actual_key
 */

import dotenv from 'dotenv';
import { Resend } from 'resend';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, '..', '.env') });

const apiKey = process.env.RESEND_API_KEY;
if (!apiKey || apiKey === 're_xxxxxxxxx') {
  console.error('Missing or placeholder RESEND_API_KEY in .env');
  console.error('Add: RESEND_API_KEY=re_your_actual_key (from resend.com → API Keys)');
  process.exit(1);
}

const resend = new Resend(apiKey);

async function main() {
  const { data, error } = await resend.emails.send({
    from: 'onboarding@resend.dev',
    to: 'snorzang65@gmail.com',
    subject: 'Hello World',
    html: '<p>Congrats on sending your <strong>first email</strong>!</p>',
  });

  if (error) {
    console.error('Resend error:', error);
    process.exit(1);
  }
  console.log('Email sent successfully:', data);
}

main();
