# Verify Hostinger email redirect

Use this to confirm that email forwarded/redirected on Hostinger is actually reaching the destination inbox.

---

## 1. Know your setup

- **Source address** (e.g. `hello@extensionshield.com`) — the one that should redirect.
- **Destination address** (e.g. `you@gmail.com`) — where mail should land.

---

## 2. Send a test email **to** the source address

- From **another account** (e.g. personal Gmail, Yahoo), send an email **to** the source address (e.g. `hello@extensionshield.com`).
- Subject/body can be anything (e.g. "Redirect test").

---

## 3. Check the destination inbox

- Open the **destination** inbox (e.g. Gmail where you expect the redirect).
- Wait 1–2 minutes (forwards can be delayed).
- **If the message appears:** Redirect is working.
- **If it doesn’t:** Check spam/junk, then continue below.

---

## 4. Check Hostinger Email / Forwarding

1. Log in to [Hostinger](https://www.hostinger.com) → **hPanel**.
2. Go to **Emails** (or **Email Accounts** / **Forwarders**).
3. Confirm the redirect/forward is **active** and points to the correct destination.
4. If there’s a **log** or **history** for that address, see if the test message was received and forwarded.

---

## 5. Optional: test with mail-tester.com

1. Go to [mail-tester.com](https://www.mail-tester.com).
2. Copy the **test address** they show (e.g. `test-xxxxx@srv1.mail-tester.com`).
3. From your **destination** inbox (e.g. Gmail), send an email **to** that mail-tester address **and set the "From" to your source address** (e.g. `hello@extensionshield.com`) if your client allows it.  
   Or: send **to** your source address from mail-tester (if they offer “send to your domain”) so the redirect runs, then you forward that to mail-tester.  
   Simpler: just send a normal test **to** your source address from any email and confirm it appears at the destination (steps 2–3). Mail-tester is mainly for deliverability/spam checks.

---

## 6. MX records (if mail never arrives)

If nothing reaches the destination:

1. In hPanel go to **Domains** → **DNS / DNS Zone** for your domain.
2. Check **MX** records: they should point to Hostinger’s mail servers (e.g. `mx1.hostinger.com` or what Hostinger shows in the Email section). If MX points elsewhere, mail may not be handled by Hostinger and the redirect won’t run.
3. Match the **priority** and **target** to what Hostinger’s docs or Email section say.

---

## Quick checklist

| Step | Action |
|------|--------|
| 1 | Send test email **to** the address that should redirect (e.g. `hello@extensionshield.com`). |
| 2 | Check **destination** inbox (and spam) within a few minutes. |
| 3 | In Hostinger, confirm the **forward/redirect** is enabled and correct. |
| 4 | If still not working, check **MX** for the domain and fix if needed. |

Once a test lands in the destination inbox, the redirect is working.
