const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");
const { readFileSync } = require("node:fs");
const { test } = require("node:test");
const vm = require("node:vm");

const script = readFileSync(`${__dirname}/../web/app.js`, "utf8");

async function dashboard(crypto) {
  const nodes = new Map();
  const element = () => ({ children: [], addEventListener(event, handler) { this[event] = handler; }, append(...items) { this.children.push(...items); }, replaceChildren(...items) { this.children = items; }, showModal() {}, close() {} });
  for (const id of ["delete-client-button", "enrollment-token-button", "client-management-status", "approval-list", "approval-status", "secret-value", "secret-dialog"]) {
    nodes.set(id, element());
  }
  const posts = [];
  const location = { hash: "#client/test-client" };
  vm.runInNewContext(script, {
    crypto, location, AbortController, URLSearchParams, clearTimeout,
    confirm: () => true,
    window: { setTimeout() {}, addEventListener() {}, location },
    document: {
      hidden: false, createElement: element,
      getElementById: (id) => nodes.get(id),
      querySelector: () => ({ content: "test-csrf" }),
      querySelectorAll: () => [],
      addEventListener() {},
    },
    async fetch(path, options) {
      if (options.method === "POST") {
        posts.push({ path, ...options, body: JSON.parse(options.body) });
        return { ok: true, json: async () => ({ enrollment_key: "new-enrollment-key" }) };
      }
      if (path.startsWith("/api/v1/history")) throw new Error("history unavailable");
      if (path === "/api/v1/registration-requests") return { ok: true, json: async () => ({ items: [{ request_id: "request-1", client_id: "new-client", replacing: false, fingerprint: "test-fingerprint", created_at: 1 }] }) };
      const value = path === "/api/v1/clients/test-client"
        ? { client: { name: "test-client", identity_source: "dynamic", enabled: true, revision: 7, heartbeat: {}, sessions: { active: 0 } } }
        : { clients: { items: [] }, enrollment: { available: true } };
      return { ok: true, json: async () => value };
    },
  });
  await new Promise(setImmediate);
  return { nodes, posts, location };
}

for (const [context, crypto] of [
  ["HTTP without randomUUID", { getRandomValues: webcrypto.getRandomValues.bind(webcrypto) }],
  ["HTTPS", webcrypto],
]) {
  test(`client management works over ${context}`, async () => {
    const { nodes, posts, location } = await dashboard(crypto);
    await nodes.get("delete-client-button").click();
    assert.equal(posts.length, 1, nodes.get("client-management-status").textContent);
    assert.equal(posts[0].path, "/api/v1/clients/test-client/delete");
    assert.equal(location.hash, "overview");
    for (const post of posts) {
      assert.equal(post.body.expected_revision, 7);
      assert.match(post.body.operation_id, /^[A-Za-z0-9_-]{1,128}$/);
      assert.equal(post.headers["X-Rustgo-CSRF-Token"], "test-csrf");
    }
    assert.equal(nodes.get("enrollment-token-button").click, undefined);
  });
}

test("approval sends authenticated review request without creating a client manually", async () => {
  const { nodes, posts } = await dashboard(webcrypto);
  const row = nodes.get("approval-list").children[0];
  assert.ok(row);
  await row.children[4].children[0].click();
  assert.equal(posts[0].path, "/api/v1/registration-requests/request-1");
  assert.equal(posts[0].body.approve, true);
  assert.equal(posts[0].headers["X-Rustgo-CSRF-Token"], "test-csrf");
  assert.match(posts[0].body.operation_id, /^[a-f0-9]{32}$/);
});
