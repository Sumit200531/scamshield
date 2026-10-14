/*
 * rules.js
 * All the scam patterns ScamShield looks for.
 *
 * Each rule has:
 *   id          - short name
 *   title       - what we show the user
 *   weight      - how many risk points it adds (total is capped at 100)
 *   patterns    - if ANY of these match, the rule is triggered
 *   alsoNeeds   - (optional) at least one of these must ALSO match
 *   explanation - why this is a red flag
 *   advice      - what the user should do
 *
 * Patterns are based on common scam messages reported in India
 * (fake KYC, digital arrest, task jobs, electricity bills, parcels etc.)
 */

const RULES = [
  {
    id: "otp-request",
    title: "Asks you to share an OTP, PIN or password",
    weight: 40,
    patterns: [
      /(share|send|tell|forward|give|provide|enter)\b[^.\n]{0,40}\b(otp|one[- ]time password|upi pin|atm pin|pin|cvv|password)\b/gi,
      /\b(otp|cvv|upi pin)\b[^.\n]{0,40}\b(share|send|tell|forward|give|provide)\b/gi
    ],
    explanation: "No real bank, delivery company or government office will ever ask you for an OTP, PIN, CVV or password. Anyone who has your OTP can take money out of your account.",
    advice: "Never share these codes with anyone, even someone claiming to be from your bank."
  },
  {
    id: "upi-receive",
    title: "Says you need to pay or enter a PIN to receive money",
    weight: 40,
    patterns: [
      /(scan|use)\b[^.\n]{0,25}\b(qr|qr code|upi)\b[^.\n]{0,40}\b(receive|get|claim|credit)/gi,
      /(enter|put)\b[^.\n]{0,20}\bpin\b[^.\n]{0,30}\b(receive|get|claim|credit)/gi,
      /\b(collect request|payment request)\b[^.\n]{0,40}\b(receive|refund|accept)/gi
    ],
    explanation: "You never need to scan a QR code or enter your UPI PIN to receive money. Entering your PIN always sends money out of your account.",
    advice: "Decline any collect request you weren't expecting, and don't scan QR codes sent by strangers."
  },
  {
    id: "kyc-blocked",
    title: "Threatens that your account, card or SIM will be blocked",
    weight: 30,
    patterns: [
      /\b(kyc|pan|aadhaar|aadhar)\b[^.\n]{0,40}\b(update|expire[sd]?|pending|blocked|suspend(ed)?|incomplete|verify)/gi,
      /\b(account|card|sim|wallet|a\/c|net ?banking)\b[^.\n]{0,30}\b(blocked|block|suspended|deactivated|closed|frozen|freeze|will be (closed|blocked|suspended))/gi
    ],
    explanation: "Scammers create panic by saying your account will be blocked unless you update KYC through their link. Real banks ask you to visit a branch or use their official app.",
    advice: "Open your bank's official app or call the number on the back of your card to check. Don't use the link in the message."
  },
  {
    id: "digital-arrest",
    title: "Claims to be police, CBI, customs or another authority",
    weight: 40,
    patterns: [
      /\b(cbi|police|customs|narcotics|ncb|enforcement directorate|ed officer|trai|cyber cell|cyber crime (branch|department)|rbi officer|income tax department|crime branch)\b/gi
    ],
    alsoNeeds: [
      /\b(arrest(ed)?|warrant|case (has been )?registered|illegal|drugs|money laundering|fir|legal action|investigation|video call|digital arrest)\b/gi
    ],
    explanation: "This looks like a \"digital arrest\" scam. Police and government agencies do not arrest people over video calls or ask for money to close a case.",
    advice: "Hang up or stop replying. Do not transfer money. Report it on 1930 or cybercrime.gov.in."
  },
  {
    id: "remote-app",
    title: "Asks you to install a screen-sharing app",
    weight: 40,
    patterns: [
      /\b(anydesk|any desk|teamviewer|team viewer|quicksupport|quick support|rustdesk|airdroid|screen ?share|screen sharing)\b/gi
    ],
    explanation: "Screen-sharing apps let the other person see and control your phone, including your OTPs and banking apps.",
    advice: "Never install an app because a caller or message asked you to. Uninstall it if you already did."
  },
  {
    id: "apk-file",
    title: "Asks you to install an APK file",
    weight: 35,
    patterns: [
      /\S+\.apk\b/gi,
      /\b(download|install)\b[^.\n]{0,30}\b(apk|this app|the app)\b/gi
    ],
    explanation: "APK files from links can contain malware that reads your SMS and OTPs. Real companies publish apps on the Play Store or App Store.",
    advice: "Don't install apps from links in messages. Only use your phone's official app store."
  },
  {
    id: "prize",
    title: "Says you won a prize, lottery or reward",
    weight: 25,
    patterns: [
      /\b(you have won|you won|winner|lottery|lucky draw|jackpot|kbc|inaam|congratulations[!,. ]+you)\b/gi,
      /\b(prize|reward|cashback|gift)\b[^.\n]{0,30}\b(claim|collect|won|selected)\b/gi
    ],
    explanation: "You can't win a lottery or lucky draw you never entered. These messages usually ask for a \"processing fee\" to release the prize.",
    advice: "Ignore it. Never pay money to receive a prize."
  },
  {
    id: "upfront-fee",
    title: "Asks for a fee or deposit before you get something",
    weight: 30,
    patterns: [
      /\b(processing fee|registration fee|refundable (fee|deposit)|security deposit|activation fee|customs (duty|fee|charges)|release fee|verification fee)\b/gi,
      /\b(pay|transfer|deposit)\b\s*(only\s*)?(rs\.?|₹|inr)\s?\d+/gi
    ],
    explanation: "Asking for a small fee first is the classic advance-fee trick. After you pay, they invent another fee, then another.",
    advice: "Don't pay. A real job, prize, refund or delivery doesn't need a fee sent to a personal UPI ID."
  },
  {
    id: "task-job",
    title: "Offers easy money for simple online tasks",
    weight: 30,
    patterns: [
      /\b(part[- ]?time|work from home|wfh|home based)\b[^\n]{0,80}\b(earn|salary|income|per day|daily|payout)\b/gi,
      /\b(like|subscribe|rate|review|follow)\b[^.\n]{0,30}\b(videos?|hotels?|products?|pages?|channels?)\b[^\n]{0,50}\b(earn|₹|rs\.?|commission|paid)/gi,
      /\bearn\b[^.\n]{0,15}(rs\.?|₹|inr)\s?\d[\d,]*[^.\n]{0,20}\b(per|a|\/)\s?(day|hour|task)/gi
    ],
    explanation: "\"Task jobs\" pay you a little at first to build trust, then ask you to \"invest\" in bigger tasks and never pay back.",
    advice: "Real employers don't hire over WhatsApp for liking videos. Don't join their Telegram groups or deposit money."
  },
  {
    id: "electricity",
    title: "Threatens to cut your electricity",
    weight: 30,
    patterns: [
      /\b(electricity|power|bijli|light)\b[^\n]{0,50}\b(disconnect(ed|ion)?|cut|will be (cut|disconnected))/gi
    ],
    explanation: "Fake electricity bill messages say your power will be cut tonight and give a personal number to call. Electricity boards don't send threats from personal mobile numbers.",
    advice: "Check your bill on your electricity board's official website or app."
  },
  {
    id: "parcel",
    title: "Says a parcel or courier is held or failed",
    weight: 20,
    patterns: [
      /\b(parcel|courier|package|shipment|consignment)\b[^\n]{0,60}\b(held|seized|on hold|failed|undeliver(ed|able)|incomplete address|update (your )?address|customs|illegal)/gi
    ],
    explanation: "Fake delivery messages ask you to pay a small \"redelivery\" fee or update your address on a fake site that steals card details.",
    advice: "Track parcels only on the courier's official website using the tracking number from the seller."
  },
  {
    id: "short-link",
    title: "Contains a shortened or hidden link",
    weight: 20,
    patterns: [
      /\b(bit\.ly|tinyurl\.com|t\.ly|cutt\.ly|is\.gd|rb\.gy|shorturl\.at|tiny\.cc|ow\.ly|rebrand\.ly)\/\S*/gi
    ],
    explanation: "Short links hide where they really go. Scammers use them so you can't see the fake website address.",
    advice: "Don't tap it. Go to the official website by typing the address yourself."
  },
  {
    id: "fake-domain",
    title: "Link looks like a fake company website",
    weight: 30,
    patterns: [
      /\b[a-z0-9-]*(sbi|hdfc|icici|axis|kotak|paytm|phonepe|amazon|flipkart|irctc|indiapost|india-post|bescom|kyc|bank|refund|aadhaar|epfo|income-?tax)[a-z0-9-]*\.(xyz|top|info|online|site|club|live|shop|click|link|buzz|icu|cfd|vip|in\.net)\b\S*/gi,
      /https?:\/\/(\d{1,3}\.){3}\d{1,3}\S*/gi
    ],
    explanation: "The link uses a company name with an unusual ending like .xyz or .top, or a raw number address. Real banks and companies use their own official domains.",
    advice: "Don't open it or enter any details there."
  },
  {
    id: "any-link",
    title: "Contains a link",
    weight: 8,
    patterns: [
      /\bhttps?:\/\/\S+/gi,
      /\bwww\.\S+/gi
    ],
    explanation: "Links in unexpected messages are the most common way scammers get you to a fake page.",
    advice: "Only open links from messages you were expecting, and check the address carefully."
  },
  {
    id: "urgency",
    title: "Creates urgency or panic",
    weight: 15,
    patterns: [
      /\b(urgent(ly)?|immediately|right now|act now|last chance|final (notice|warning|reminder)|today itself|before midnight|tonight|turant|abhi)\b/gi,
      /\bwithin\s+\d+\s*(hours?|hrs?|minutes?|mins?)\b/gi
    ],
    explanation: "Scammers rush you so you don't stop to think or check with someone.",
    advice: "Slow down. A real problem will still be there after you verify it."
  },
  {
    id: "secrecy",
    title: "Asks you to keep it secret",
    weight: 20,
    patterns: [
      /\b(don'?t|do not|never) (tell|inform|share this with) (anyone|anybody|your family|family|bank|dad|papa|mom|mum|parents)\b/gi,
      /\bkeep (this|it) (confidential|secret|between us)\b/gi
    ],
    explanation: "Asking you not to tell family or the bank is a big red flag. Scammers want to stop anyone from warning you.",
    advice: "Talk to a family member or friend before doing anything."
  },
  {
    id: "family-emergency",
    title: "Someone claims to be family on a new number",
    weight: 25,
    patterns: [
      /\b(hi|hello|hey) (mum|mom|mummy|mama|dad|papa|beta)\b/gi,
      /\b(new number|lost my phone|changed my number|phone (is )?broken|this is my new)\b/gi
    ],
    explanation: "Scammers pretend to be a relative with a new number and then ask for money urgently.",
    advice: "Call your family member on their old number, or ask a question only they would know."
  },
  {
    id: "money-request",
    title: "Asks you to send money",
    weight: 20,
    patterns: [
      /\b(send|transfer|pay)\b\s*(me\s*)?(some money|money|(rs\.?|₹|inr)?\s?\d{3,}[\d,]*)/gi
    ],
    explanation: "Any message that asks you to send money, especially in a hurry, needs to be checked with the person directly.",
    advice: "Call the person on a number you already know before sending anything."
  },
  {
    id: "personal-number",
    title: "Asks you to call or WhatsApp a personal mobile number",
    weight: 12,
    patterns: [
      /\b(call|contact|whatsapp|message|reach)\b[^.\n]{0,40}(\+?91[- ]?)?[6-9]\d{9}\b/gi
    ],
    explanation: "Real companies use toll-free or official numbers, not a random 10-digit mobile number.",
    advice: "Find the company's official number on its website and call that instead."
  }
];

// Phrases real companies use. These lower the score a little.
const SAFE_SIGNALS = [
  {
    title: "Tells you NOT to share the code",
    points: -25,
    patterns: [
      /\b(do not|don'?t|never) share\b[^.\n]{0,30}\b(otp|pin|code|password)?/gi,
      /\b(bank|we) (will )?never (ask|call)\b/gi
    ]
  }
];

// Sample messages for the demo buttons. All made up.
const SAMPLE_MESSAGES = [
  {
    label: "KYC update",
    text: "Dear Customer, your bank account will be BLOCKED today due to incomplete KYC. Update your PAN immediately: http://bank-kyc-update.xyz/verify or call 9876543210. Ignore if already done."
  },
  {
    label: "Digital arrest",
    text: "This is Inspector Sharma from Mumbai Cyber Crime Branch. A parcel in your name with illegal drugs has been seized by customs. An FIR is registered and an arrest warrant is issued. Join the video call within 2 hours to avoid arrest. Do not tell anyone about this investigation."
  },
  {
    label: "Part-time job",
    text: "Hello! We are hiring for part time work from home. Just like YouTube videos and earn Rs 3000 per day. No experience needed. Pay a refundable registration fee of Rs 500 to start. Join our Telegram: bit.ly/earn-daily-job"
  },
  {
    label: "Electricity bill",
    text: "Dear consumer, your electricity power will be disconnected tonight at 9:30 pm because your previous month bill was not updated. Please immediately contact our electricity officer 8123456789. Thank you."
  },
  {
    label: "Lottery win",
    text: "CONGRATULATIONS! You have won Rs 25,00,000 in the KBC lucky draw. To claim your prize, pay the processing fee of Rs 9,999 and scan the QR code to receive the amount."
  },
  {
    label: "Real bank OTP",
    text: "482913 is your OTP for login to your bank account. Valid for 5 minutes. Do not share this OTP with anyone. Bank will never ask for your OTP."
  }
];
