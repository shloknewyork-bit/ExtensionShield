# Hostinger + Cloudflare DNS — what to fix

From your Cloudflare DNS and Hostinger "Connect Domain" screens, use this checklist so nothing is missing.

---

## ✅ Already OK

| Item | Status |
|------|--------|
| **MX (receive email)** | Hostinger shows "Connected". Your Cloudflare MX records for `mx1.hostinger.com` (priority 5) and `mx2.hostinger.com` (priority 10) are correct. |
| **Resend (sending)** | `resend._domainkey` TXT is in Cloudflare for Resend DKIM. No change needed for Resend. |
| **DMARC** | You have `_dmarc` TXT with `v=DMARC1; p=none`. Optional: set TTL to 3600 if Hostinger expects it. |

---

## ⚠️ Fix: DKIM (Hostinger) — "Increase email deliverability"

Hostinger says **"No records"** for DKIM because your **DKIM CNAMEs are proxied** in Cloudflare. Mail servers need to resolve the CNAME directly; proxying can break DKIM.

**Do this in Cloudflare:**

1. Go to **DNS** → **Records** for `extensionshield.com`.
2. Find the three **CNAME** records:
   - `hostingermail-a._domainkey` → `hostingermail-a.dkim.mail.hostinger.com`
   - `hostingermail-b._domainkey` → `hostingermail-b.dkim.mail.hostinger.com`
   - `hostingermail-c._domainkey` → `hostingermail-c.dkim.mail.hostinger.com`
3. For **each** of these three, click **Edit** and set **Proxy status** to **DNS only** (grey cloud). Save.

After DNS propagates (a few minutes), in Hostinger click **Check status** on "Connect Domain". "Increase email deliverability" should turn green.

---

## ⚠️ Fix: SPF (Hostinger) — "Protect your email reputation"

Hostinger shows **"No records"** for SPF. You may already have an SPF TXT at the root in Cloudflare (e.g. `v=spf1 include:_spf.mail.h...`). If Hostinger still says "No records":

1. In Hostinger, open the **"Protect your reputation"** tab and copy the **exact** SPF record they show (Type, Name, Value).
2. In Cloudflare **DNS**:
   - If you already have a TXT for `@` with `v=spf1`, edit it so it **includes Hostinger**. Example: `v=spf1 include:_spf.mail.hostinger.com ~all` (or whatever Hostinger’s "Expected records" show). If you use Resend or others, keep them: `v=spf1 include:_spf.mail.hostinger.com include:resend.com ~all`.
   - If you have no SPF TXT at `@`, add one with the value Hostinger gives you.
3. Save, wait a few minutes, then **Check status** in Hostinger.

---

## Optional: DMARC TTL

If Hostinger’s "Message authentication" tab expects DMARC TTL **3600** and your current record has TTL **30**, edit the `_dmarc` TXT in Cloudflare and set TTL to **3600** (or Auto). Then re-check in Hostinger.

---

## Summary

| What | Action |
|------|--------|
| **DKIM** | Set the three Hostinger DKIM CNAMEs to **DNS only** in Cloudflare (no proxy). |
| **SPF** | Ensure root `@` has an SPF TXT that **includes Hostinger** (from Hostinger’s "Protect your reputation" tab). |
| **DMARC TTL** | Optionally set to 3600 to match Hostinger. |
| **MX** | No change. |
| **Resend** | No change. |

After these changes, run **Check status** in Hostinger until all three sections (Receive emails, Protect your reputation, Increase email deliverability) are green.
