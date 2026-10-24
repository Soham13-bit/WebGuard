const REQUIRED_CHECKS = Object.freeze([
  "Transport",
  "Embedded credentials",
  "Internationalized hostname",
  "Host format",
  "Port"
]);

const INDICATOR_RULES = Object.freeze({
  "Embedded credentials": Object.freeze({
    weight: 35,
    severity: "Medium",
    group: "address-presentation",
    reason:
      "Credentials embedded in a URL can obscure which host the browser will visit."
  }),
  "Internationalized hostname": Object.freeze({
    weight: 30,
    severity: "Medium",
    group: "address-presentation",
    reason:
      "An internationalized hostname deserves a closer visual check for confusingly similar characters."
  }),
  Port: Object.freeze({
    weight: 10,
    severity: "Low",
    group: null,
    reason:
      "A non-default port is less common, but can be legitimate and is not evidence of maliciousness by itself."
  })
});

const GROUP_CAPS = Object.freeze({
  "address-presentation": 50
});

const MAX_POINTS = 60;

function unavailableResult(reason, missingChecks = []) {
  return {
    available: false,
    reason,
    missingChecks,
    score: null,
    severity: "Unavailable",
    points: null,
    maxPoints: MAX_POINTS,
    findings: []
  };
}

function severityForScore(score) {
  if (score < 25) {
    return "Low";
  }
  if (score < 60) {
    return "Medium";
  }
  return "High";
}

function isValidCheck(check) {
  return (
    check &&
    typeof check === "object" &&
    typeof check.name === "string" &&
    REQUIRED_CHECKS.includes(check.name) &&
    typeof check.flagged === "boolean" &&
    check.status === (check.flagged ? "Observation" : "No issue found") &&
    typeof check.detail === "string" &&
    check.detail.trim().length > 0
  );
}

export function calculateUrlRisk(urlCheckResult) {
  if (
    !urlCheckResult ||
    typeof urlCheckResult !== "object" ||
    urlCheckResult.error ||
    !Array.isArray(urlCheckResult.checks)
  ) {
    return unavailableResult("URL check data is unavailable.");
  }

  if (!urlCheckResult.checks.every(isValidCheck)) {
    return unavailableResult("URL check data is invalid.");
  }

  const checksByName = new Map();
  for (const check of urlCheckResult.checks) {
    const existing = checksByName.get(check.name);
    if (existing && existing.flagged !== check.flagged) {
      return unavailableResult(
        "Conflicting duplicate URL check data is unavailable."
      );
    }
    if (!existing || (!existing.flagged && check.flagged)) {
      checksByName.set(check.name, check);
    }
  }

  const missingChecks = REQUIRED_CHECKS.filter(
    (name) => !checksByName.has(name)
  );
  if (missingChecks.length > 0) {
    return unavailableResult(
      "Some URL checks are missing; a complete estimate cannot be calculated.",
      missingChecks
    );
  }

  const findings = [];
  const groupTotals = new Map();
  let independentPoints = 0;

  for (const name of Object.keys(INDICATOR_RULES)) {
    const check = checksByName.get(name);
    if (!check.flagged) {
      continue;
    }

    const rule = INDICATOR_RULES[name];
    findings.push({
      name,
      evidence: check.detail,
      severity: rule.severity,
      weight: rule.weight,
      group: rule.group,
      reason: rule.reason
    });

    if (rule.group) {
      groupTotals.set(
        rule.group,
        (groupTotals.get(rule.group) || 0) + rule.weight
      );
    } else {
      independentPoints += rule.weight;
    }
  }

  const groupedPoints = Array.from(groupTotals, ([group, points]) =>
    Math.min(points, GROUP_CAPS[group])
  ).reduce((total, points) => total + points, 0);
  const points = Math.min(MAX_POINTS, groupedPoints + independentPoints);
  const score = Math.max(
    0,
    Math.min(100, Math.round((points / MAX_POINTS) * 100))
  );

  return {
    available: true,
    reason: null,
    missingChecks: [],
    score,
    severity: severityForScore(score),
    points,
    maxPoints: MAX_POINTS,
    findings
  };
}
