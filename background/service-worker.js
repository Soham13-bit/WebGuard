"use strict";

import { createNavigationHistoryStore } from "../popup/navigation-history.mjs";
import {
  formatNavigationRegistrationFailure,
  registerNavigationListeners
} from "./navigation-listeners.mjs";

const HISTORY_KEY = "webGuardNavigationHistory";
const MAX_STORED_EVENTS = 100;
const storageArea =
  globalThis.chrome &&
  chrome.storage &&
  chrome.storage.session &&
  typeof chrome.storage.session.get === "function" &&
  typeof chrome.storage.session.set === "function"
    ? chrome.storage.session
    : null;
const historyStore = storageArea
  ? createNavigationHistoryStore(storageArea, {
      key: HISTORY_KEY,
      limit: MAX_STORED_EVENTS
    })
  : null;

if (storageArea && typeof storageArea.setAccessLevel === "function") {
  storageArea
    .setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" })
    .catch(() =>
      console.error("[WebGuard] Could not restrict session storage access.")
    );
}

function recordEvent(event) {
  if (!historyStore || !navigationRegistration.available) {
    return;
  }

  historyStore.record(event).then(
    () => notifyPopup(),
    () => console.error("[WebGuard] Navigation event could not be stored.")
  );
}

function notifyPopup() {
  chrome.runtime.sendMessage(
    { type: "WEBGUARD_NAVIGATION_HISTORY_UPDATED" },
    () => {
      void chrome.runtime.lastError;
    }
  );
}

const navigationHandlers = {
  onBeforeNavigate(details) {
    if (details.frameId === 0) {
      recordEvent({ ...details, eventType: "navigation-start" });
    }
  },
  onBeforeRedirect(details) {
    if (details.frameId === 0) {
      recordEvent({ ...details, eventType: "redirect" });
    }
  },
  onCommitted(details) {
    if (details.frameId === 0) {
      recordEvent({ ...details, eventType: "navigation-committed" });
    }
  },
  onCompleted(details) {
    if (details.frameId === 0) {
      recordEvent({ ...details, eventType: "navigation-completed" });
    }
  },
  onErrorOccurred(details) {
    if (details.frameId === 0) {
      recordEvent({ ...details, eventType: "navigation-error" });
    }
  },
  onCreatedNavigationTarget(details) {
    recordEvent({
      ...details,
      tabId: details.targetTabId,
      eventType: "new-tab"
    });
  }
};
const navigationRegistration = storageArea
  ? registerNavigationListeners(chrome.webNavigation, navigationHandlers)
  : {
      available: false,
      unavailableEvents: ["chrome.storage.session (requires Chrome 102 or later)"],
      apiErrors: [],
      registrationErrors: [],
      cleanupFailedEvents: []
    };

if (!navigationRegistration.available) {
  console.error(
    "[WebGuard] Navigation monitoring is unavailable: " +
      formatNavigationRegistrationFailure(navigationRegistration)
  );
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== "WEBGUARD_GET_NAVIGATION_HISTORY") {
    return false;
  }

  if (!historyStore || !navigationRegistration.available) {
    sendResponse({
      ok: false,
      available: false,
      reason: !storageArea
        ? "Navigation monitoring requires session storage."
        : "Navigation monitoring is unavailable because required webNavigation events could not be registered."
    });
    return false;
  }

  if (!Number.isInteger(message.tabId)) {
    sendResponse({
      ok: false,
      available: false,
      reason: "The active tab ID is unavailable."
    });
    return false;
  }

  historyStore
    .getForTab(message.tabId)
    .then((events) =>
      sendResponse({ ok: true, available: true, events })
    )
    .catch(() => {
      console.error("[WebGuard] Navigation history could not be loaded.");
      sendResponse({
        ok: false,
        available: false,
        reason: "Navigation history is unavailable."
      });
    });
  return true;
});

chrome.runtime.onInstalled.addListener((details) => {
  if (navigationRegistration.available && historyStore) {
    console.info(
      "[WebGuard] Extension installed or updated; passive navigation monitoring is ready.",
      { reason: details.reason }
    );
  } else {
    console.warn(
      "[WebGuard] Extension installed or updated, but passive navigation monitoring is unavailable.",
      { reason: details.reason }
    );
  }
});
