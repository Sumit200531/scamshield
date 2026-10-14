/*
 * ScamShield
 * Next Byte Hacks V5
 *
 * Paste a suspicious message -> we check it against the rules in rules.js,
 * give it a risk score from 0 to 100, highlight the risky parts,
 * and explain each red flag in simple words.
 *
 * Everything happens in the browser. No server, no API, no data sent anywhere.
 */

// ------------------------------------------------------------
// Constants
// ------------------------------------------------------------

const MAX_SCORE = 100;
const MANY_FLAGS_BONUS = 10;   // extra points when 3 or more red flags show up together
const MANY_FLAGS_COUNT = 3;

const RISK_LEVELS = {
  low: {
    label: "Looks low risk",
    className: "level-low",
    summary: "We didn't find common scam patterns. Still be careful with links and never share OTPs or PINs."
  },
  medium: {
    label: "Suspicious",
    className: "level-medium",
    summary: "This message has some warning signs. Verify it through an official app or number before doing anything."
  },
  high: {
    label: "Likely a scam",
    className: "level-high",
    summary: "This message matches several known scam patterns. Don't click links, don't call the number, and don't pay or share anything."
  }
};

// ------------------------------------------------------------
// Getting elements
// ------------------------------------------------------------

const messageInput = document.getElementById("message-input");
const checkButton = document.getElementById("check-btn");
const clearButton = document.getElementById("clear-btn");
const sampleButtonsContainer = document.getElementById("sample-buttons");
const resultsSection = document.getElementById("results");
const toast = document.getElementById("toast");

let toastTimer = null;

// ------------------------------------------------------------
// Helper functions
// ------------------------------------------------------------

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

// Checks if the words right before a match say "do not", "never" etc.
// So "do not share your OTP" doesn't count as asking for the OTP.
function isNegated(text, matchStart) {
  const textBefore = text.slice(Math.max(0, matchStart - 15), matchStart).toLowerCase();
  return /(\bnot|n'?t|\bnever)\s*$/.test(textBefore);
}

// Runs a list of regex patterns on the text and returns every match with its position
function findMatches(text, patterns, skipNegated) {
  const matches = [];

  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      if (skipNegated && isNegated(text, match.index)) {
        continue;
      }
      matches.push({
        start: match.index,
        end: match.index + match[0].length,
        text: match[0]
      });
    }
  }

  return matches;
}

function getRiskLevel(score) {
  if (score >= 50) return RISK_LEVELS.high;
  if (score >= 20) return RISK_LEVELS.medium;
  return RISK_LEVELS.low;
}

// ------------------------------------------------------------
// Main analysis
// ------------------------------------------------------------

function analyzeMessage(text) {
  const triggeredRules = [];
  const safeSignalsFound = [];
  let score = 0;

  for (const rule of RULES) {
    // the OTP rule should ignore "do not share your OTP"
    const skipNegated = rule.id === "otp-request" || rule.id === "upi-receive";
    const matches = findMatches(text, rule.patterns, skipNegated);

    if (matches.length === 0) continue;

    // some rules need two things together (e.g. "police" AND "arrest")
    if (rule.alsoNeeds) {
      const extraMatches = findMatches(text, rule.alsoNeeds, false);
      if (extraMatches.length === 0) continue;
      matches.push(...extraMatches);
    }

    triggeredRules.push({ rule: rule, matches: matches });
    score += rule.weight;
  }

  // if there's a scarier link rule, the plain "contains a link" one is not needed
  const hasScaryLink = triggeredRules.some(item => item.rule.id === "short-link" || item.rule.id === "fake-domain");
  if (hasScaryLink) {
    const index = triggeredRules.findIndex(item => item.rule.id === "any-link");
    if (index !== -1) {
      score -= triggeredRules[index].rule.weight;
      triggeredRules.splice(index, 1);
    }
  }

  if (triggeredRules.length >= MANY_FLAGS_COUNT) {
    score += MANY_FLAGS_BONUS;
  }

  for (const signal of SAFE_SIGNALS) {
    const matches = findMatches(text, signal.patterns, false);
    if (matches.length > 0) {
      safeSignalsFound.push(signal);
      score += signal.points;
    }
  }

  // keep the score between 0 and 100
  score = Math.max(0, Math.min(MAX_SCORE, score));

  // biggest red flags first
  triggeredRules.sort((a, b) => b.rule.weight - a.rule.weight);

  return {
    score: score,
    level: getRiskLevel(score),
    triggeredRules: triggeredRules,
    safeSignals: safeSignalsFound
  };
}

// ------------------------------------------------------------
// Highlighting the risky parts of the message
// ------------------------------------------------------------

function buildHighlightedMessage(text, triggeredRules) {
  // collect every match from every rule
  let ranges = [];
  for (const item of triggeredRules) {
    for (const match of item.matches) {
      ranges.push({ start: match.start, end: match.end, title: item.rule.title });
    }
  }

  if (ranges.length === 0) {
    return escapeHtml(text);
  }

  // sort by start position, then merge overlapping ranges
  ranges.sort((a, b) => a.start - b.start);
  const merged = [ranges[0]];

  for (let i = 1; i < ranges.length; i++) {
    const last = merged[merged.length - 1];
    const current = ranges[i];

    if (current.start <= last.end) {
      last.end = Math.max(last.end, current.end);
      if (!last.title.includes(current.title)) {
        last.title += " / " + current.title;
      }
    } else {
      merged.push(current);
    }
  }

  // build the html piece by piece
  let html = "";
  let position = 0;

  for (const range of merged) {
    html += escapeHtml(text.slice(position, range.start));
    html += `<mark title="${escapeHtml(range.title)}">${escapeHtml(text.slice(range.start, range.end))}</mark>`;
    position = range.end;
  }
  html += escapeHtml(text.slice(position));

  return html;
}

// ------------------------------------------------------------
// Rendering results
// ------------------------------------------------------------

function buildWarningText(result) {
  if (result.triggeredRules.length === 0) {
    return "I checked a message with ScamShield and it didn't find common scam signs, but remember: never share OTPs or PINs with anyone.";
  }

  const topFlags = result.triggeredRules
    .slice(0, 3)
    .map(item => item.rule.title.toLowerCase())
    .join("; ");

  return `Warning: I checked a message with ScamShield and it looks like a scam (risk ${result.score}/100). ` +
         `Red flags: ${topFlags}. ` +
         `If you get a message like this, don't click the link, don't call the number and never share your OTP or PIN. ` +
         `If you've lost money, call 1930 or report at cybercrime.gov.in.`;
}

function renderResults(text, result) {
  const level = result.level;
  const flagCount = result.triggeredRules.length;

  let flagsHtml = "";
  for (const item of result.triggeredRules) {
    flagsHtml += `
      <li class="flag">
        <div class="flag-head">
          <h4>${escapeHtml(item.rule.title)}</h4>
          <span class="flag-points">+${item.rule.weight}</span>
        </div>
        <p>${escapeHtml(item.rule.explanation)}</p>
        <p class="flag-advice"><strong>What to do:</strong> ${escapeHtml(item.rule.advice)}</p>
      </li>`;
  }

  let safeHtml = "";
  for (const signal of result.safeSignals) {
    safeHtml += `<li class="safe-signal">${escapeHtml(signal.title)} <span>${signal.points}</span></li>`;
  }

  const flagsSection = flagCount > 0
    ? `<h3>${flagCount} red flag${flagCount === 1 ? "" : "s"} found</h3><ul class="flag-list">${flagsHtml}</ul>`
    : `<h3>No red flags found</h3>`;

  const safeSection = result.safeSignals.length > 0
    ? `<h3>Good signs</h3><ul class="safe-list">${safeHtml}</ul>`
    : "";

  resultsSection.innerHTML = `
    <div class="verdict ${level.className}">
      <div class="verdict-top">
        <div>
          <span class="verdict-eyebrow">Risk score</span>
          <div class="verdict-score"><span id="score-number">${result.score}</span><small>/100</small></div>
        </div>
        <span class="verdict-badge">${level.label}</span>
      </div>
      <div class="meter" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${result.score}" aria-label="Risk score">
        <div class="meter-fill" style="width: ${result.score}%"></div>
      </div>
      <p class="verdict-summary">${level.summary}</p>
    </div>

    <div class="result-block">
      <h3>Your message</h3>
      <p class="hint">Highlighted parts triggered a red flag. Hover or tap to see which one.</p>
      <div class="highlighted-message">${buildHighlightedMessage(text, result.triggeredRules)}</div>
    </div>

    <div class="result-block">
      ${flagsSection}
      ${safeSection}
    </div>

    <div class="result-block share-block">
      <h3>Warn your family</h3>
      <p class="hint">Copy this and send it to your family group so they can spot the same scam.</p>
      <textarea id="warning-text" rows="4" readonly>${escapeHtml(buildWarningText(result))}</textarea>
      <button id="copy-btn" class="btn-outline" type="button">Copy warning</button>
    </div>
  `;

  document.getElementById("copy-btn").addEventListener("click", copyWarning);
  resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ------------------------------------------------------------
// Button actions
// ------------------------------------------------------------

function checkMessage() {
  const text = messageInput.value.trim();

  if (text === "") {
    resultsSection.innerHTML = `<p class="empty-state">Paste a message above, or try one of the samples, then press Check message.</p>`;
    messageInput.focus();
    return;
  }

  const result = analyzeMessage(text);
  renderResults(text, result);
}

function clearMessage() {
  messageInput.value = "";
  resultsSection.innerHTML = "";
  messageInput.focus();
}

function copyWarning() {
  const warningBox = document.getElementById("warning-text");

  navigator.clipboard.writeText(warningBox.value)
    .then(() => showToast("Copied. Paste it in your family group."))
    .catch(() => {
      // some browsers block clipboard, so just select the text instead
      warningBox.select();
      showToast("Press Ctrl+C to copy the selected text.");
    });
}

function showToast(message) {
  toast.textContent = message;
  toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.hidden = true; }, 2500);
}

function createSampleButtons() {
  SAMPLE_MESSAGES.forEach(sample => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "sample-btn";
    button.textContent = sample.label;
    button.addEventListener("click", () => {
      messageInput.value = sample.text;
      checkMessage();
    });
    sampleButtonsContainer.appendChild(button);
  });
}

// ------------------------------------------------------------
// Event listeners + start
// ------------------------------------------------------------

checkButton.addEventListener("click", checkMessage);
clearButton.addEventListener("click", clearMessage);

// Ctrl + Enter also checks the message
messageInput.addEventListener("keydown", event => {
  if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
    checkMessage();
  }
});

createSampleButtons();
