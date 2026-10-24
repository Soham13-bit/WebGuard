import assert from "node:assert/strict";
import test from "node:test";
import {
  CURATED_HOSTS,
  extractCuratedRules,
  parseEasyListMetadata
} from "./update-resource-rules.mjs";

const revision = "a".repeat(40);
const sourceBodies = Object.fromEntries(
  Object.entries(CURATED_HOSTS).map(([name, hosts]) => [
    name,
    {
      rulesText: hosts.map((host) => "||" + host + "^").join("\n"),
      exceptionTexts: [],
      url:
        "https://raw.githubusercontent.com/easylist/easylist/" +
        revision +
        "/" +
        (name === "EasyList"
          ? "easylist/easylist_adservers.txt"
          : "easyprivacy/easyprivacy_trackingservers_general.txt")
    }
  ])
);

function extract(sources = sourceBodies) {
  return extractCuratedRules({
    sources,
    sourceRevision: revision,
    generatedAt: "2026-10-12T06:00:00.000Z",
    lastModified: "2026-10-12T05:32:22.000Z",
    expiresAt: "2026-10-16T05:32:22.000Z"
  });
}

test("extracts only the reviewed host-wide rules in deterministic order", () => {
  const result = extract();

  assert.equal(result.rules.length, 17);
  assert.deepEqual(
    result.rules.map((rule) => rule.domain),
    result.rules.map((rule) => rule.domain).slice().sort()
  );
  assert.ok(
    result.rules.every(
      (rule) =>
        rule.rule === "||" + rule.domain + "^" &&
        rule.revision === revision
    )
  );
  assert.deepEqual(
    result.rules
      .filter((rule) =>
        [
          "ad.doubleclick.net",
          "fls.doubleclick.net",
          "g.doubleclick.net",
          "bidswitch.net",
          "bluekai.com",
          "demdex.net",
          "everesttech.net"
        ].includes(rule.domain)
      )
      .map(({ domain, source }) => [domain, source]),
    [
      ["ad.doubleclick.net", "EasyList"],
      ["bidswitch.net", "EasyPrivacy"],
      ["bluekai.com", "EasyPrivacy"],
      ["demdex.net", "EasyPrivacy"],
      ["everesttech.net", "EasyPrivacy"],
      ["fls.doubleclick.net", "EasyList"],
      ["g.doubleclick.net", "EasyList"]
    ]
  );
});

test("does not treat contextual, path, wildcard, or malformed rules as host-wide", () => {
  const sources = structuredClone(sourceBodies);
  const host = CURATED_HOSTS.EasyList[0];
  sources.EasyList.rulesText = sources.EasyList.rulesText
    .replace("||" + host + "^", "||" + host + "^$third-party")
    .concat("\n||" + host + "/path^\n||*.example.com^\n||bad..example^\n");

  assert.throws(() => extract(sources), /no longer contains/);
});

test("rejects matching exceptions, including contextual exceptions, conservatively", () => {
  const sources = structuredClone(sourceBodies);
  const host = CURATED_HOSTS.EasyList[0];
  sources.EasyList.exceptionTexts = [
    "@@||sub." + host + "^$script"
  ];

  assert.throws(() => extract(sources), /matching exception/);
});

test("does not treat an exception lookalike as a conflicting exception", () => {
  const sources = structuredClone(sourceBodies);
  sources.EasyList.exceptionTexts = [
    "@@||not" + CURATED_HOSTS.EasyList[0] + "^"
  ];

  assert.equal(extract(sources).rules.length, 17);
});

test("fails closed when selected source rules disappear or provenance is malformed", () => {
  const sources = structuredClone(sourceBodies);
  sources.EasyPrivacy.rulesText = "";
  assert.throws(() => extract(sources), /no longer contains/);
  assert.throws(
    () => extractCuratedRules({ ...extractInput(), sourceRevision: "bad" }),
    /source revision/
  );
  assert.throws(
    () =>
      extract({
        ...structuredClone(sourceBodies),
        EasyPrivacy: {
          ...structuredClone(sourceBodies.EasyPrivacy),
          url: "https://example.invalid/rules"
        }
      }),
    /Missing or invalid source text/
  );
});

function extractInput() {
  return {
    sources: sourceBodies,
    sourceRevision: revision,
    generatedAt: "2026-10-12T06:00:00.000Z",
    lastModified: "2026-10-12T05:32:22.000Z",
    expiresAt: "2026-10-16T05:32:22.000Z"
  };
}

test("validates feed title, version, revision, timestamps, expiry, and freshness", () => {
  const feed = [
    "[Adblock Plus 2.0]",
    "! Version: 202610120532",
    "! Title: EasyList",
    "! Last modified: 12 Oct 2026 05:32 UTC",
    "! Expires: 4 days (update frequency)",
    "! Commit: " + revision
  ].join("\n");
  const metadata = parseEasyListMetadata(
    feed,
    new Date("2026-10-12T06:00:00.000Z")
  );

  assert.equal(metadata.revision, revision);
  assert.equal(metadata.expiresAt, "2026-10-16T05:32:00.000Z");
  assert.throws(
    () =>
      parseEasyListMetadata(
        feed.replace("Title: EasyList", "Title: Unknown"),
        new Date("2026-10-12T06:00:00.000Z")
      ),
    /metadata/
  );
  assert.throws(
    () =>
      parseEasyListMetadata(feed, new Date("2026-10-17T06:00:00.000Z")),
    /stale/
  );
});
