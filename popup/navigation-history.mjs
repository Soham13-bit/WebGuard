export const MAX_NAVIGATION_HISTORY = 100;
export const NAVIGATION_HISTORY_KEY = "webGuardNavigationHistory";

const MAX_REDIRECTS_PER_NAVIGATION = 20;
const NEW_TAB_ASSOCIATION_WINDOW_MS = 15_000;

function safeTimestamp(value) {
  return Number.isFinite(value) && value >= 0 ? value : Date.now();
}

export function sanitizeNavigationUrl(value) {
  if (typeof value !== "string" || value.length === 0) {
    return { url: null, availability: "unavailable" };
  }

  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return { url: null, availability: "restricted" };
    }

    parsed.username = "";
    parsed.password = "";
    parsed.search = "";
    parsed.hash = "";
    return {
      url: (parsed.origin + parsed.pathname).slice(0, 2048),
      availability: "available"
    };
  } catch {
    return { url: null, availability: "unavailable" };
  }
}

function navigationIdFor(details) {
  return typeof details.navigationId === "string" && details.navigationId
    ? details.navigationId
    : null;
}

function navigationRecordId(tabId, navigationId, timestamp, historyLength) {
  return navigationId
    ? "navigation:" + tabId + ":" + navigationId
    : "navigation:" + tabId + ":unknown:" + timestamp + ":" + historyLength;
}

function findNavigation(history, tabId, navigationId) {
  if (!navigationId) {
    return null;
  }
  return history.find(
    (record) => record.tabId === tabId && record.navigationId === navigationId
  );
}

function findNewTabTarget(history, tabId, url, timestamp) {
  const safeUrl = sanitizeNavigationUrl(url);
  return history.find(
    (record) =>
      record.openedInNewTab &&
      record.tabId === tabId &&
      record.navigationId === null &&
      timestamp >= record.updatedAt &&
      timestamp - record.updatedAt <= NEW_TAB_ASSOCIATION_WINDOW_MS &&
      (record.destination === safeUrl.url ||
        record.destinationAvailability !== "available" ||
        safeUrl.availability !== "available")
  );
}

function createRecord(history, details, timestamp, destination) {
  const navigationId = navigationIdFor(details);
  return {
    id: navigationRecordId(
      details.tabId,
      navigationId,
      timestamp,
      history.length
    ),
    tabId: details.tabId,
    sourceTabId: null,
    sourceFrameId: null,
    navigationId,
    openedInNewTab: false,
    destination: destination.url,
    destinationAvailability: destination.availability,
    navigationStatus: "observed",
    redirectEvents: [],
    startedAt: timestamp,
    updatedAt: timestamp,
    eventCount: 0
  };
}

function touch(record, timestamp) {
  record.updatedAt = Math.max(record.updatedAt, timestamp);
  record.eventCount += 1;
}

function getOrCreateNavigation(history, details, timestamp, destination) {
  const navigationId = navigationIdFor(details);
  let record = findNavigation(history, details.tabId, navigationId);
  if (record) {
    return record;
  }

  if (details.eventType === "navigation-start") {
    record = findNewTabTarget(
      history,
      details.tabId,
      details.url,
      timestamp
    );
    if (record) {
      record.navigationId = navigationId;
      record.id = navigationRecordId(
        record.tabId,
        navigationId,
        record.startedAt,
        history.indexOf(record)
      );
      return record;
    }
  }

  record = createRecord(history, details, timestamp, destination);
  history.push(record);
  return record;
}

export function recordNavigationEvent(historyInput, details) {
  const history = Array.isArray(historyInput)
    ? historyInput.map((record) => ({
        ...record,
        redirectEvents: Array.isArray(record.redirectEvents)
          ? record.redirectEvents.map((event) => ({ ...event }))
          : []
      }))
    : [];
  if (!details || !Number.isInteger(details.tabId) || details.tabId < 0) {
    return history;
  }

  const timestamp = safeTimestamp(details.timeStamp);
  const destination = sanitizeNavigationUrl(
    details.eventType === "redirect"
      ? details.redirectUrl
      : details.url
  );

  if (details.eventType === "new-tab") {
    if (!Number.isInteger(details.targetTabId) || details.targetTabId < 0) {
      return history;
    }
    const target = sanitizeNavigationUrl(details.url);
    const id =
      "new-tab:" + details.targetTabId + ":" + timestamp + ":" + history.length;
    history.push({
      id,
      tabId: details.targetTabId,
      sourceTabId:
        Number.isInteger(details.sourceTabId) && details.sourceTabId >= 0
          ? details.sourceTabId
          : null,
      sourceFrameId: Number.isInteger(details.sourceFrameId)
        ? details.sourceFrameId
        : null,
      navigationId: null,
      openedInNewTab: true,
      destination: target.url,
      destinationAvailability: target.availability,
      navigationStatus: "target-observed",
      redirectEvents: [],
      startedAt: timestamp,
      updatedAt: timestamp,
      eventCount: 1
    });
    return history
      .sort((left, right) => right.updatedAt - left.updatedAt)
      .slice(0, MAX_NAVIGATION_HISTORY);
  }

  const record = getOrCreateNavigation(
    history,
    details,
    timestamp,
    destination
  );
  touch(record, timestamp);

  if (details.eventType === "navigation-start") {
    record.destination = destination.url;
    record.destinationAvailability = destination.availability;
    record.navigationStatus = "in-progress";
  } else if (details.eventType === "redirect") {
    const from = sanitizeNavigationUrl(details.url);
    if (record.redirectEvents.length < MAX_REDIRECTS_PER_NAVIGATION) {
      record.redirectEvents.push({
        from: from.url,
        fromAvailability: from.availability,
        to: destination.url,
        toAvailability: destination.availability,
        timestamp
      });
      record.redirectEvents.sort((left, right) => left.timestamp - right.timestamp);
    }
    record.destination = destination.url;
    record.destinationAvailability = destination.availability;
    record.navigationStatus = "redirect-observed";
  } else if (details.eventType === "navigation-committed") {
    record.destination = destination.url;
    record.destinationAvailability = destination.availability;
    record.navigationStatus = "committed";
  } else if (details.eventType === "navigation-completed") {
    record.destination = destination.url;
    record.destinationAvailability = destination.availability;
    record.navigationStatus = "completed";
  } else if (details.eventType === "navigation-error") {
    record.destination = destination.url;
    record.destinationAvailability = destination.availability;
    record.navigationStatus = "failed";
  }

  return history
    .sort((left, right) => right.updatedAt - left.updatedAt)
    .slice(0, MAX_NAVIGATION_HISTORY);
}

export function getNavigationHistoryForTab(history, tabId) {
  if (!Array.isArray(history) || !Number.isInteger(tabId)) {
    return [];
  }

  return history
    .filter((record) => record.tabId === tabId || record.sourceTabId === tabId)
    .sort((left, right) => right.updatedAt - left.updatedAt);
}

export function createNavigationHistoryStore(
  storageArea,
  { key = NAVIGATION_HISTORY_KEY, limit = MAX_NAVIGATION_HISTORY } = {}
) {
  let operationQueue = Promise.resolve();

  function enqueue(operation) {
    const result = operationQueue.then(operation);
    operationQueue = result.then(
      () => undefined,
      () => undefined
    );
    return result;
  }

  return {
    record(details) {
      return enqueue(async () => {
        const stored = await storageArea.get(key);
        const history = Array.isArray(stored && stored[key])
          ? stored[key]
          : [];
        const updated = recordNavigationEvent(history, details).slice(
          0,
          Math.max(1, limit)
        );
        await storageArea.set({ [key]: updated });
        return updated;
      });
    },
    getForTab(tabId) {
      return enqueue(async () => {
        const stored = await storageArea.get(key);
        return getNavigationHistoryForTab(
          Array.isArray(stored && stored[key]) ? stored[key] : [],
          tabId
        );
      });
    }
  };
}
