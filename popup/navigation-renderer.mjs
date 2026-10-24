function displayDestination(destination, availability) {
  if (availability === "restricted") {
    return "Restricted browser page (URL not exposed)";
  }
  if (availability !== "available" || !destination) {
    return "Destination unavailable";
  }
  return destination;
}

function navigationDescription(record) {
  if (record.redirectEvents.length > 0) {
    return (
      record.redirectEvents.length +
      " redirect event(s) confirmed by Chrome navigation events"
    );
  }
  if (record.navigationStatus === "completed") {
    return "Navigation completed; no redirect event was observed";
  }
  if (record.navigationStatus === "failed") {
    return "Navigation failed; no redirect event was observed";
  }
  if (record.navigationStatus === "target-observed") {
    return "New-tab target observed; navigation details may be unavailable";
  }
  return "Navigation observed; no redirect event observed so far";
}

export function renderNavigationHistory(container, events, options = {}) {
  container.replaceChildren();
  const document = container.ownerDocument;
  const summary = document.createElement("p");
  summary.className = "navigation-summary";

  if (!options.available) {
    summary.textContent =
      options.reason ||
      "Navigation monitoring is unavailable; required permission or session data is missing.";
    container.append(summary);
    return;
  }

  if (!Array.isArray(events) || events.length === 0) {
    summary.textContent =
      "No navigation events are available for this tab. Events before installation, restricted by Chrome, or not exposed to the extension cannot be recovered.";
    container.append(summary);
    return;
  }

  const visibleEvents = events.slice(0, options.limit || events.length);
  summary.textContent =
    visibleEvents.length +
    " observed navigation record(s). Monitoring may miss events or details Chrome does not expose. Redirects and new tabs do not by themselves indicate maliciousness.";
  container.append(summary);

  visibleEvents.forEach((record) => {
    const item = document.createElement("article");
    item.className = "navigation-record";

    const heading = document.createElement("strong");
    heading.textContent = record.openedInNewTab
      ? "New tab opened"
      : "Navigation";
    item.append(heading);

    const destination = document.createElement("p");
    destination.textContent =
      "Observed destination: " +
      displayDestination(record.destination, record.destinationAvailability);
    item.append(destination);

    const tabs = document.createElement("small");
    tabs.textContent =
      "Tab " +
      record.tabId +
      (record.sourceTabId === null
        ? ""
        : " · opened from tab " + record.sourceTabId);
    item.append(tabs);

    const status = document.createElement("small");
    status.textContent = navigationDescription(record);
    item.append(status);

    if (record.navigationId) {
      const navigationId = document.createElement("small");
      navigationId.textContent = "Navigation ID: " + record.navigationId;
      item.append(navigationId);
    } else if (record.openedInNewTab) {
      const missingId = document.createElement("small");
      missingId.textContent = "Navigation ID unavailable for the tab-target event.";
      item.append(missingId);
    }

    record.redirectEvents.forEach((redirect, index) => {
      const redirectEvidence = document.createElement("small");
      redirectEvidence.textContent =
        "Observed redirect " +
        (index + 1) +
        ": " +
        displayDestination(redirect.from, redirect.fromAvailability) +
        " → " +
        displayDestination(redirect.to, redirect.toAvailability);
      item.append(redirectEvidence);
    });
    container.append(item);
  });
}
