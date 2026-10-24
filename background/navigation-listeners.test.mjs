import assert from "node:assert/strict";
import test from "node:test";
import {
  formatNavigationRegistrationFailure,
  registerNavigationListeners,
  REQUIRED_NAVIGATION_EVENTS
} from "./navigation-listeners.mjs";

function createNavigationApi() {
  const listeners = new Map();
  const webNavigation = {};
  for (const name of REQUIRED_NAVIGATION_EVENTS) {
    listeners.set(name, []);
    webNavigation[name] = {
      addListener(handler) {
        listeners.get(name).push(handler);
      },
      removeListener(handler) {
        listeners.set(
          name,
          listeners.get(name).filter((registered) => registered !== handler)
        );
      }
    };
  }
  return { webNavigation, listeners };
}

function createHandlers() {
  return Object.fromEntries(
    REQUIRED_NAVIGATION_EVENTS.map((name) => [name, () => {}])
  );
}

test("registers every required navigation event", () => {
  const { webNavigation, listeners } = createNavigationApi();
  const result = registerNavigationListeners(webNavigation, createHandlers());

  assert.equal(result.available, true);
  for (const name of REQUIRED_NAVIGATION_EVENTS) {
    assert.equal(listeners.get(name).length, 1, name);
  }
});

test("reports a missing required event without registering partial monitoring", () => {
  const { webNavigation, listeners } = createNavigationApi();
  delete webNavigation.onBeforeRedirect;
  const result = registerNavigationListeners(webNavigation, createHandlers());

  assert.deepEqual(result, {
    available: false,
    unavailableEvents: ["onBeforeRedirect"],
    apiErrors: [],
    registrationErrors: [],
    cleanupFailedEvents: []
  });
  for (const name of REQUIRED_NAVIGATION_EVENTS) {
    assert.equal(listeners.get(name).length, 0, name);
  }
});

test("rolls back previously registered events when registration throws", () => {
  const { webNavigation, listeners } = createNavigationApi();
  const addListener = webNavigation.onCommitted.addListener;
  webNavigation.onCommitted.addListener = (handler) => {
    addListener.call(webNavigation.onCommitted, handler);
    throw new Error("registration failed");
  };
  const result = registerNavigationListeners(webNavigation, createHandlers());

  assert.deepEqual(result, {
    available: false,
    unavailableEvents: ["onCommitted"],
    apiErrors: [],
    registrationErrors: [
      { event: "onCommitted", error: "Error: registration failed" }
    ],
    cleanupFailedEvents: []
  });
  for (const name of REQUIRED_NAVIGATION_EVENTS) {
    assert.equal(listeners.get(name).length, 0, name);
  }
});

test("reports missing API and missing handler dependencies", () => {
  assert.deepEqual(registerNavigationListeners(undefined, createHandlers()), {
    available: false,
    unavailableEvents: ["webNavigation"]
  });

  const { webNavigation } = createNavigationApi();
  const handlers = createHandlers();
  delete handlers.onCompleted;
  const result = registerNavigationListeners(webNavigation, handlers);
  assert.equal(result.available, false);
  assert.deepEqual(result.unavailableEvents, ["onCompleted"]);
  assert.deepEqual(result.registrationErrors, []);
});

test("reports throwing event getters and readable registration diagnostics", () => {
  const { webNavigation } = createNavigationApi();
  Object.defineProperty(webNavigation, "onBeforeRedirect", {
    get() {
      throw new TypeError("event is not exposed");
    }
  });
  const missing = registerNavigationListeners(webNavigation, createHandlers());
  assert.deepEqual(missing.unavailableEvents, ["onBeforeRedirect"]);
  assert.deepEqual(missing.apiErrors, [
    { event: "onBeforeRedirect", error: "TypeError: event is not exposed" }
  ]);
  assert.match(
    formatNavigationRegistrationFailure(missing),
    /unavailable: onBeforeRedirect; could not inspect onBeforeRedirect: TypeError: event is not exposed/
  );

  const { webNavigation: throwingApi } = createNavigationApi();
  throwingApi.onCommitted.addListener = () => {
    throw new TypeError("permission denied by browser");
  };
  const failed = registerNavigationListeners(throwingApi, createHandlers());
  assert.match(
    formatNavigationRegistrationFailure(failed),
    /registration failed for onCommitted: TypeError: permission denied by browser/
  );
});

test("formats missing storage diagnostics without object coercion", () => {
  const message = formatNavigationRegistrationFailure({
    available: false,
    unavailableEvents: ["chrome.storage.session (requires Chrome 102 or later)"],
    registrationErrors: [],
    cleanupFailedEvents: []
  });
  assert.equal(
    message,
    "unavailable: chrome.storage.session (requires Chrome 102 or later)"
  );
  assert.doesNotMatch(message, /\[object Object\]/);
});
