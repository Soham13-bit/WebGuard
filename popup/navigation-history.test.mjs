import assert from "node:assert/strict";
import test from "node:test";
import {
  createNavigationHistoryStore,
  getNavigationHistoryForTab,
  recordNavigationEvent,
  sanitizeNavigationUrl
} from "./navigation-history.mjs";

function event(eventType, overrides = {}) {
  return {
    eventType,
    tabId: 7,
    navigationId: "nav-1",
    frameId: 0,
    timeStamp: 100,
    url: "https://source.example/start",
    ...overrides
  };
}

test("tracks a new-tab target and associates its later navigation", () => {
  let history = recordNavigationEvent([], {
    eventType: "new-tab",
    tabId: 12,
    targetTabId: 12,
    sourceTabId: 7,
    sourceFrameId: 0,
    url: "https://destination.example/watch?token=private",
    timeStamp: 100
  });
  history = recordNavigationEvent(
    history,
    event("navigation-start", {
      tabId: 12,
      navigationId: "target-nav",
      timeStamp: 110,
      url: "https://destination.example/watch?other=private"
    })
  );

  assert.equal(history.length, 1);
  assert.equal(history[0].openedInNewTab, true);
  assert.equal(history[0].sourceTabId, 7);
  assert.equal(history[0].tabId, 12);
  assert.equal(history[0].navigationId, "target-nav");
  assert.equal(history[0].destination, "https://destination.example/watch");
  assert.deepEqual(getNavigationHistoryForTab(history, 7), [history[0]]);
});

test("associates confirmed redirects with their navigation ID", () => {
  let history = recordNavigationEvent(
    [],
    event("navigation-start", { timeStamp: 10 })
  );
  history = recordNavigationEvent(
    history,
    event("redirect", {
      timeStamp: 20,
      url: "https://source.example/start",
      redirectUrl: "https://middle.example/next"
    })
  );
  history = recordNavigationEvent(
    history,
    event("redirect", {
      timeStamp: 30,
      url: "https://middle.example/next",
      redirectUrl: "https://destination.example/final"
    })
  );
  history = recordNavigationEvent(
    history,
    event("navigation-committed", {
      timeStamp: 40,
      url: "https://destination.example/final"
    })
  );

  assert.equal(history.length, 1);
  assert.equal(history[0].redirectEvents.length, 2);
  assert.equal(history[0].destination, "https://destination.example/final");
  assert.equal(history[0].navigationStatus, "committed");
  assert.deepEqual(
    history[0].redirectEvents.map((redirect) => redirect.to),
    [
      "https://middle.example/next",
      "https://destination.example/final"
    ]
  );
});

test("keeps same navigation identifiers separate across tabs", () => {
  let history = recordNavigationEvent(
    [],
    event("navigation-start", { tabId: 7, navigationId: "shared-id" })
  );
  history = recordNavigationEvent(
    history,
    event("navigation-start", {
      tabId: 8,
      navigationId: "shared-id",
      timeStamp: 101,
      url: "https://other.example/"
    })
  );
  history = recordNavigationEvent(
    history,
    event("redirect", {
      tabId: 7,
      navigationId: "shared-id",
      timeStamp: 102,
      redirectUrl: "https://final.example/"
    })
  );

  assert.equal(history.length, 2);
  assert.equal(getNavigationHistoryForTab(history, 7)[0].redirectEvents.length, 1);
  assert.equal(getNavigationHistoryForTab(history, 8)[0].redirectEvents.length, 0);
});

test("orders redirects by observed timestamp, not callback arrival", () => {
  let history = recordNavigationEvent(
    [],
    event("navigation-start", { timeStamp: 10 })
  );
  history = recordNavigationEvent(
    history,
    event("redirect", {
      timeStamp: 30,
      url: "https://middle.example/",
      redirectUrl: "https://final.example/"
    })
  );
  history = recordNavigationEvent(
    history,
    event("redirect", {
      timeStamp: 20,
      url: "https://source.example/",
      redirectUrl: "https://middle.example/"
    })
  );

  assert.deepEqual(
    history[0].redirectEvents.map((redirect) => redirect.timestamp),
    [20, 30]
  );
  assert.equal(history[0].updatedAt, 30);
});

test("bounds stored navigation history", () => {
  let history = [];
  for (let index = 0; index < 5; index += 1) {
    history = recordNavigationEvent(
      history,
      event("navigation-start", {
        tabId: index,
        navigationId: "nav-" + index,
        timeStamp: index + 1,
        url: "https://site" + index + ".example/"
      })
    );
  }

  assert.equal(history.length, 5);
  const session = { value: {} };
  const store = createNavigationHistoryStore(
    {
      async get(key) {
        return { [key]: session.value[key] };
      },
      async set(values) {
        Object.assign(session.value, values);
      }
    },
    { key: "history", limit: 2 }
  );
  return Promise.all(
    history.map((record) =>
      store.record({
        eventType: "navigation-start",
        tabId: record.tabId,
        navigationId: record.navigationId,
        timeStamp: record.startedAt,
        url: record.destination
      })
    )
  ).then(async () => {
    const stored = await store.getForTab(4);
    assert.equal(session.value.history.length, 2);
    assert.equal(stored.length, 1);
    assert.equal(stored[0].tabId, 4);
  });
});

test("keeps new-tab evidence distinct from redirect evidence", () => {
  const history = recordNavigationEvent([], {
    eventType: "new-tab",
    tabId: 12,
    targetTabId: 12,
    sourceTabId: 7,
    sourceFrameId: 2,
    url: "https://destination.example/",
    timeStamp: 100
  });

  assert.equal(history[0].openedInNewTab, true);
  assert.equal(history[0].redirectEvents.length, 0);
  assert.equal(history[0].navigationStatus, "target-observed");
});

test("represents missing navigation IDs and restricted destinations", () => {
  const history = recordNavigationEvent(
    [],
    event("navigation-start", {
      navigationId: undefined,
      url: "chrome://newtab/",
      timeStamp: 100
    })
  );

  assert.equal(history[0].navigationId, null);
  assert.equal(history[0].destination, null);
  assert.equal(history[0].destinationAvailability, "restricted");
  assert.deepEqual(sanitizeNavigationUrl(""), {
    url: null,
    availability: "unavailable"
  });
});

test("removes credentials, query strings, and fragments before storing URLs", () => {
  const sanitized = sanitizeNavigationUrl(
    "https://alice:secret@site.example/private/path?token=secret#section"
  );

  assert.deepEqual(sanitized, {
    url: "https://site.example/private/path",
    availability: "available"
  });
});

test("session history remains readable through a new store after worker restart", async () => {
  const session = { value: {} };
  const storageArea = {
    async get(key) {
      return { [key]: session.value[key] };
    },
    async set(values) {
      Object.assign(session.value, values);
    }
  };
  const firstWorkerStore = createNavigationHistoryStore(storageArea, {
    key: "history"
  });
  await firstWorkerStore.record(
    event("navigation-start", {
      timeStamp: 100,
      url: "https://destination.example/page?session=secret"
    })
  );

  const restartedWorkerStore = createNavigationHistoryStore(storageArea, {
    key: "history"
  });
  const restored = await restartedWorkerStore.getForTab(7);

  assert.equal(restored.length, 1);
  assert.equal(restored[0].destination, "https://destination.example/page");
});

test("reports completed navigation without claiming a redirect occurred", () => {
  let history = recordNavigationEvent(
    [],
    event("navigation-start", { timeStamp: 100 })
  );
  history = recordNavigationEvent(
    history,
    event("navigation-completed", { timeStamp: 120 })
  );

  assert.equal(history[0].navigationStatus, "completed");
  assert.deepEqual(history[0].redirectEvents, []);
});
