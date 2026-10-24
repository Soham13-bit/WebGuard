export function getUrlCheckResults(url) {
  let page;
  try {
    page = new URL(url);
  } catch {
    return {
      checks: [],
      error: "The active tab URL is not valid."
    };
  }

  if (page.protocol !== "http:" && page.protocol !== "https:") {
    return { checks: [], error: null };
  }

  const isHttps = page.protocol === "https:";
  const checks = [];
  const addCheck = (name, isFlagged, detail) => {
    checks.push({
      name,
      status: isFlagged ? "Observation" : "No issue found",
      detail,
      flagged: isFlagged
    });
  };

  addCheck(
    "Transport",
    !isHttps,
    isHttps
      ? "The address uses HTTPS. This does not prove the site is trustworthy."
      : "The address uses HTTP, so the connection is not encrypted."
  );

  const hasCredentials = page.username.length > 0 || page.password.length > 0;
  addCheck(
    "Embedded credentials",
    hasCredentials,
    hasCredentials
      ? "The URL contains username or password information."
      : "No username or password is embedded in the URL."
  );

  const hasPunycode = page.hostname
    .split(".")
    .some((label) => label.toLowerCase().startsWith("xn--"));
  addCheck(
    "Internationalized hostname",
    hasPunycode,
    hasPunycode
      ? "The hostname contains a punycode label; inspect the displayed domain carefully."
      : "No punycode labels were found in the hostname."
  );

  const isIpAddress =
    page.hostname.startsWith("[") ||
    /^(?:\d{1,3}\.){3}\d{1,3}$/.test(page.hostname);
  addCheck(
    "Host format",
    isIpAddress,
    isIpAddress
      ? "The URL uses an IP address instead of a conventional domain name."
      : "The URL uses a domain name rather than an IP literal."
  );

  const expectedPort = isHttps ? "443" : "80";
  const hasNonstandardPort = Boolean(page.port && page.port !== expectedPort);
  addCheck(
    "Port",
    hasNonstandardPort,
    hasNonstandardPort
      ? "The URL specifies a non-default port (" + page.port + ")."
      : "No non-default port is specified."
  );

  return { checks, error: null };
}
