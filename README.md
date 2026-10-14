# ScamShield 🛡️

**Paste a suspicious message. Find out if it's a scam, and why.**

Built for Next Byte Hacks V5.

## The problem

Scam messages are everywhere: fake KYC updates, "your electricity will be cut tonight", part-time "like videos and earn" jobs, lottery wins, and "digital arrest" calls from fake police officers. The people most likely to fall for them, like parents, grandparents and first-time smartphone users, usually don't know the warning signs. By the time they ask someone, the money is often gone.

## What it does

ScamShield is a simple website where you paste any SMS, WhatsApp message or email. It:

- Gives the message a **risk score from 0 to 100**: low risk, suspicious, or likely a scam
- **Highlights the exact words** that look risky
- Explains each **red flag in plain language** and says what to do
- Notices **good signs** too (for example, a real bank OTP says "do not share")
- Creates a **warning message you can copy** and send to your family group
- Shows **where to report**: helpline 1930, cybercrime.gov.in, and Chakshu on Sanchar Saathi

**Privacy:** everything runs in your browser. The message is never uploaded anywhere.

## Scam types it detects

| Scam type | Example red flags |
|---|---|
| OTP / PIN theft | "share the OTP", "enter UPI PIN to receive" |
| Fake KYC / account block | "KYC expired", "account will be blocked" |
| Digital arrest | "CBI", "customs", "arrest warrant", "video call" |
| Remote access | AnyDesk, TeamViewer, screen sharing |
| Malware apps | links to `.apk` files |
| Lottery / prize | "you have won", "lucky draw", "KBC" |
| Advance fee | "processing fee", "refundable deposit" |
| Task jobs | "like videos and earn ₹3000 per day" |
| Electricity bill | "power will be disconnected tonight" |
| Parcel / courier | "parcel held at customs" |
| Fake family member | "hi mom, this is my new number" |
| Suspicious links | short links, `.xyz`/`.top` domains, raw IP addresses |
| Pressure tactics | "urgent", "within 2 hours", "don't tell anyone" |

## How to run it

No installation needed.

1. Clone or download this repo:
   ```
   git clone https://github.com/YOUR-USERNAME/scamshield.git
   ```
2. Open `index.html` in any browser.

Or use the live version: `https://YOUR-USERNAME.github.io/scamshield/`

## How it works

- `rules.js` has 19 rules. Each one has regex patterns, a weight (risk points), an explanation and advice.
- `script.js` runs every rule on the message, adds up the points, and caps the score at 100.
  - Some rules need two things together. For example, "police" alone is fine, but "police" + "arrest warrant" triggers the digital arrest rule.
  - "Do not share your OTP" is ignored by the OTP rule, so real bank messages don't get flagged.
  - 3 or more red flags together add a bonus, because real scams usually stack tricks.
- Matches from all rules are merged and highlighted in the message.

## Built with

HTML, CSS, vanilla JavaScript, regular expressions. No frameworks, no backend, no APIs.

## Files

```
index.html   page layout
style.css    styles (light + dark mode)
rules.js     all the scam detection rules + sample messages
script.js    analysis, scoring, highlighting, rendering
```

## Future plans

- Hindi and other Indian language support
- Browser extension that checks messages in WhatsApp Web and Gmail
- Android app that can check SMS directly
- Screenshot upload with OCR, since many people forward screenshots
- Let users report new scam patterns so the rules stay up to date

## Disclaimer

ScamShield uses pattern matching. A low score doesn't guarantee a message is safe. Always verify using official numbers or apps.
