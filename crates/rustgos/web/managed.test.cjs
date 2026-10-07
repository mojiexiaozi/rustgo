const assert = require('node:assert/strict');
const { test } = require('node:test');
const { readFileSync } = require('node:fs');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
function setup() {
  const nodes = new Map();
  const element = () => ({ children: [], dataset: {}, attributes: {}, value: '', addEventListener(e, f) { this[e] = f; }, append(...a) { this.children.push(...a); }, replaceChildren(...a) { this.children = a; }, removeChild(child) { this.children.splice(this.children.indexOf(child), 1); }, insertBefore(child, anchor) { const previous = this.children.indexOf(child); if (previous >= 0) this.children.splice(previous, 1); const index = anchor ? this.children.indexOf(anchor) : this.children.length; this.children.splice(index, 0, child); }, setAttribute(k, v) { this.attributes[k] = v; }, getAttribute(k) { return this.attributes[k]; }, reset() {}, });
  for (const id of ['managed-status', 'managed-operation-status', 'managed-rows', 'managed-form', 'managed-fields', 'managed-kind', 'managed-submit', 'managed-apply']) nodes.set(id, element());
  nodes.get('managed-kind').value = 'tcp';
  const location = { hash: '#client/node' };
  const posts = [];
  const ctx = { crypto: webcrypto, location, AbortController, URLSearchParams, clearTimeout, window: { location, addEventListener() {} }, document: { hidden: true, getElementById: id => nodes.get(id), querySelector: () => null, querySelectorAll: () => [], createElement: element, createElementNS: (_ns, _name) => element(), addEventListener() {} }, fetch: async (path, opts) => { posts.push({path, body: JSON.parse(opts.body)}); return {ok: true, json: async () => ({})}; } };
  ctx.confirm = () => true;
  for (const id of ['client-title', 'client-detail-summary', 'client-identity', 'client-detail-metrics', 'approval-list']) nodes.set(id, element());
  const source = readFileSync(`${__dirname}/app.js`, 'utf8').replace(/\r\n/g, '\n').replace('  showRoute();\n  requestPoll();', '  globalThis.api = { state, clientCard, sortedClients, renderClientDetail, chartNode, deleteClient, refreshApprovals, renderManaged: typeof renderManaged === "function" ? renderManaged : undefined, mutateManaged: typeof mutateManaged === "function" ? mutateManaged : undefined, refreshManaged: typeof refreshManaged === "function" ? refreshManaged : undefined };');
  vm.runInNewContext(source, ctx);
  return { ...ctx.api, nodes, posts, location, ctx };
}
const detail = () => ({ online: true, supported: true, snapshot: {revision: 4, applied_revision: 4, configuration: {p2p_enabled: true, tunnels: [{name:'<tcp>',protocol:'tcp',local_addr:'127.0.0.1:80',remote_port:8080}],exports:[{name:'share',protocol:'udp',local_addr:'127.0.0.1:53',allowed_peers:[]}],forwards:[{name:'use',peer:'other',export:'share',listen_addr:'127.0.0.1:9000'}]},results:[{kind:'tunnel',name:'<tcp>',state:'ready'},{kind:'export',name:'share',state:'failed',error:'bind error'}]}});
const content = node => [node.textContent || '', ...node.children.map(content)].join(' ');
const client = (name, uid) => ({name, uid, display_name: '<img src=x onerror=alert(1)>', local_ip: '192.168.1.10', identity_source: 'dynamic', revision: 3, heartbeat: {}, telemetry: {}, traffic: {}, inventory: {exports: {total: 0}, forwards: {total: 0}, tunnels: {items: [], total: 0}}, sessions: {active: 0}, paths: {}});
test('managed controls separate adding from applying the current configuration', () => {
  const html = readFileSync(`${__dirname}/index.html`, 'utf8');
  assert.match(html, /id="managed-submit"[^>]*type="submit"[^>]*>新增<\/button>/);
  assert.match(html, /id="managed-apply"[^>]*type="button"[^>]*>保存并应用<\/button>/);
});
test('charts visibly show units, scale limits, and current minimum maximum values', () => {
  const app = setup();
  const chart = { children: [], attributes: {}, replaceChildren(...items) { this.children = items; }, append(...items) { this.children.push(...items); }, setAttribute(k, v) { this.attributes[k] = v; } };
  app.nodes.set('test-chart', chart);
  app.chartNode('test-chart', [
    { timestamp_unix_millis: 1, value: 2500 },
    { timestamp_unix_millis: 2, value: 5000 },
  ], [], { title: 'CPU 历史', unit: '%', range: '1 小时', primaryLabel: 'CPU', formatValue: value => `${(value / 100).toFixed(1)}%`, maxValue: 10000 });
  const visible = content(chart);
  assert.match(visible, /单位：%/);
  assert.match(visible, /当前 50\.0%/);
  assert.match(visible, /最低 25\.0%/);
  assert.match(visible, /最高 50\.0%/);
  assert.match(visible, /100\.0%/);
  assert.match(visible, /0\.0%/);
});
test('same display names render metadata safely while links and deletion retain routing identity', async () => {
  const app = setup();
  for (const [name, uid] of [['route-one', 'uid-one'], ['route-two', 'uid-two']]) {
    const value = client(name, uid), card = app.clientCard(value);
    assert.equal(card.children[0].children[0].children[0].textContent, value.display_name);
    assert.equal(card.children[0].children[0].children[0].href, `#client/${name}`);
    assert.ok(content(card).includes(uid)); assert.ok(content(card).includes(value.local_ip));
    assert.equal(card.innerHTML, undefined);
    await app.deleteClient(value);
    assert.equal(app.posts.at(-1).path, `/api/v1/clients/${name}/delete`);
  }
});
test('search matches display name, UID, local IP and legacy route', () => {
  const app = setup(), value = client('legacy-route', 'uid-one');
  for (const query of ['IMG', 'UID-ONE', '192.168.1.10', 'legacy-route']) {
    app.state.clientSearch = query;
    assert.equal(app.sortedClients({items: [value]}).length, 1, query);
  }
});
test('client details expose display name, UID and IP as text and legacy identity is explicit', () => {
  const app = setup(), value = client('route-one', 'uid-one');
  app.renderClientDetail({client:value, sessions:{items:[]}});
  assert.equal(app.nodes.get('client-title').textContent, value.display_name);
  assert.ok(content(app.nodes.get('client-identity')).includes(value.uid));
  assert.ok(content(app.nodes.get('client-identity')).includes(value.local_ip));
  value.uid = null; value.local_ip = null; value.display_name = undefined;
  app.renderClientDetail({client:value, sessions:{items:[]}});
  assert.equal(app.nodes.get('client-title').textContent, value.name);
  assert.match(content(app.nodes.get('client-identity')), /旧版/);
});
test('all kinds render safe names, addresses, ACL and actual results', () => {
  const app = setup(); app.renderManaged('node', detail());
  const output = content(app.nodes.get('managed-rows'));
  for (const value of ['<tcp>', '127.0.0.1:80', '8080', 'share', '所有已授权客户端', 'other', '127.0.0.1:9000', 'bind error', '等待']) assert.ok(output.includes(value), value);
  assert.equal(app.nodes.get('managed-rows').children.length, 3);
  for (const row of app.nodes.get('managed-rows').children) {
    const [edit, remove] = row.children.at(-1).children;
    assert.equal(edit.textContent, '编辑');
    assert.equal(remove.textContent, '删除');
  }
});
test('deletion carries exact name, kind and expected revision; duplicate submit suppressed', async () => {
  const app = setup(); app.renderManaged('node', detail());
  await Promise.all([app.mutateManaged({action:'delete',kind:'tunnel',name:'<tcp>'}), app.mutateManaged({action:'delete',kind:'tunnel',name:'<tcp>'})]);
  assert.equal(app.posts.length, 1);
  assert.equal(app.posts[0].body.expected_revision, 4);
  assert.equal(app.posts[0].body.name, '<tcp>');
  assert.equal(app.posts[0].body.kind, 'tunnel');
});
test('client memory and storage show used and total capacity', () => {
  const app = setup(), value = client('route-one', 'uid-one');
  value.telemetry = {
    cpu_basis_points: 100,
    memory_used_bytes: 1024,
    memory_total_bytes: 2048,
    disk_used_bytes: 4096,
    disk_total_bytes: 8192,
    network_sent_bytes_per_second: 0,
    network_received_bytes_per_second: 0,
  };
  app.renderClientDetail({client:value, sessions:{items:[]}});
  const output = content(app.nodes.get('client-detail-metrics'));
  assert.match(output, /1\.0 KiB \/ 2\.0 KiB/);
  assert.match(output, /4\.0 KiB \/ 8\.0 KiB/);
});
test('save and apply resubmits the current server configuration without add fields', async () => {
  const app = setup(); app.renderManaged('node', detail());
  await app.nodes.get('managed-apply').click();
  assert.equal(app.posts.length, 1);
  assert.deepEqual(app.posts[0].body, {
    operation_id: app.posts[0].body.operation_id,
    expected_revision: 4,
    action: 'apply',
    kind: 'configuration',
  });
});
test('existing server tunnel is edited in its own row and updated', async () => {
  const app = setup(); app.renderManaged('node', detail());
  const addFields = app.nodes.get('managed-fields').children;
  const tunnelRow = app.nodes.get('managed-rows').children[0];
  await tunnelRow.children.at(-1).children[0].click();
  assert.equal(app.nodes.get('managed-fields').children, addFields);
  assert.equal(app.state.managed.editing.fields.name.value, '<tcp>');
  assert.equal(tunnelRow.children[4].children[0], app.state.managed.editing.fields.remote_port);
  assert.equal(app.state.managed.editing.fields.remote_port.value, '8080');
  app.state.managed.editing.fields.remote_port.value = '9090';
  await tunnelRow.children.at(-1).children[0].click();
  assert.equal(app.posts.length, 1);
  assert.equal(app.posts[0].body.action, 'update');
  assert.equal(app.posts[0].body.kind, 'tunnel');
  assert.equal(app.posts[0].body.name, '<tcp>');
  assert.equal(app.posts[0].body.item.remote_port, 9090);
});
test('polling preserves inline draft and cancel restores the row without a request', async () => {
  const app = setup(); app.renderManaged('node', detail());
  const row = app.nodes.get('managed-rows').children[0];
  await row.children.at(-1).children[0].click();
  const input = app.state.managed.editing.fields.remote_port;
  input.value = '9090';
  const rows = app.nodes.get('managed-rows');
  const replace = rows.replaceChildren;
  rows.replaceChildren = (...items) => {
    assert.ok(items.includes(row), 'refresh must not detach the active editor');
    replace.call(rows, ...items);
  };
  app.renderManaged('node', detail());
  rows.replaceChildren = replace;
  assert.equal(app.nodes.get('managed-rows').children[0], row);
  assert.equal(input.value, '9090');
  await row.children.at(-1).children[1].click();
  assert.equal(app.state.managed.editing, null);
  assert.match(content(app.nodes.get('managed-rows').children[0]), /8080/);
  assert.equal(app.posts.length, 0);
});
test('inline save retains the draft revision after a newer server snapshot', async () => {
  const app = setup(); app.renderManaged('node', detail());
  const row = app.nodes.get('managed-rows').children[0];
  await row.children.at(-1).children[0].click();
  const newer = detail(); newer.snapshot.revision = 5;
  app.renderManaged('node', newer);
  await row.children.at(-1).children[0].click();
  assert.equal(app.posts[0].body.expected_revision, 4);
});
test('inline export and forward save typed fields without replacing the add form', async () => {
  for (const [index, kind] of [[1, 'export'], [2, 'forward']]) {
    const app = setup(); app.renderManaged('node', detail());
    const row = app.nodes.get('managed-rows').children[index];
    await row.children.at(-1).children[0].click();
    const fields = app.state.managed.editing.fields;
    if (kind === 'export') fields.allowed_peers.value = 'one, two';
    else fields.peer.value = 'new-peer';
    await row.children.at(-1).children[0].click();
    assert.equal(app.posts[0].body.kind, kind);
    if (kind === 'export') assert.deepEqual(app.posts[0].body.item.allowed_peers, ['one', 'two']);
    else assert.equal(app.posts[0].body.item.peer, 'new-peer');
  }
});
test('failed inline save keeps input and restores editing after refresh', async () => {
  const app = setup(); app.renderManaged('node', detail());
  const row = app.nodes.get('managed-rows').children[0];
  await row.children.at(-1).children[0].click();
  const input = app.state.managed.editing.fields.remote_port;
  input.value = '9090';
  app.ctx.fetch = async () => { throw new Error('save failed'); };
  await row.children.at(-1).children[0].click();
  assert.match(content(app.nodes.get('managed-operation-status')), /save failed/);
  assert.equal(input.value, '9090');
  assert.equal(input.disabled, true);
  app.renderManaged('node', detail());
  assert.equal(input.disabled, false);
  assert.equal(app.nodes.get('managed-rows').children[0], row);
});
test('offline or stale report cannot appear ready; polling preserves input nodes', () => {
  const app = setup(); const value = detail(); app.renderManaged('node', value);
  const fields = app.nodes.get('managed-fields').children;
  value.online = false; value.snapshot.applied_revision = 3; app.renderManaged('node', value);
  assert.match(app.nodes.get('managed-status').textContent, /离线/);
  assert.ok(!content(app.nodes.get('managed-rows')).includes('已就绪'));
  assert.equal(app.nodes.get('managed-fields').children, fields);
});

test('offline application failures remain visible as previous failures', () => {
  const app = setup(); const value = detail(); value.online = false;
  app.renderManaged('node', value);
  assert.match(content(app.nodes.get('managed-rows')), /上次失败：bind error/);
});

test('pending target status includes its reason', () => {
  const app = setup(); const value = detail();
  value.snapshot.results.push({kind:'forward',name:'use',state:'pending',error:'目标客户端离线'});
  app.renderManaged('node',value);
  assert.match(content(app.nodes.get('managed-rows')), /目标客户端离线/);
});
test('unsupported client and unsynced client disable mutations', async () => {
  const app = setup(); const value = detail(); value.supported = false; app.renderManaged('node', value);
  assert.match(app.nodes.get('managed-status').textContent, /升级/);
  await app.mutateManaged({action:'delete',kind:'tunnel',name:'<tcp>'}); assert.equal(app.posts.length, 0);
  app.renderManaged('node', {online:false,supported:null,snapshot:null});
  assert.equal(app.nodes.get('managed-submit').disabled, true);
});
test('type-specific forms post numeric ports, ACL arrays and forward targets', async () => {
  for (const [kind, values, expected] of [
    ['tcp', {name:'web',local_addr:'127.0.0.1:80',remote_port:'8080'}, {remote_port:8080,protocol:'tcp'}],
    ['udp', {name:'dns',local_addr:'127.0.0.1:53',remote_port:'8053'}, {remote_port:8053,protocol:'udp'}],
    ['export', {name:'share',protocol:'tcp',local_addr:'127.0.0.1:80',allowed_peers:'one, two'}, {allowed_peers:['one','two']}],
    ['forward', {name:'use',peer:'other',export:'share',listen_addr:'127.0.0.1:9000'}, {peer:'other',export:'share'}],
  ]) {
    const app = setup(); app.renderManaged('node', detail());
    app.nodes.get('managed-kind').value = kind; app.nodes.get('managed-kind').change();
    for (const [key,value] of Object.entries(values)) app.state.managed.fields[key].value = value;
    await app.nodes.get('managed-form').submit({preventDefault() {}});
    assert.equal(app.posts[0].body.kind,['tcp','udp'].includes(kind) ? 'tunnel' : kind);
    if (['tcp','udp'].includes(kind)) assert.equal(app.state.managed.fields.protocol,undefined);
    for (const [key,value] of Object.entries(expected)) assert.deepEqual(app.posts[0].body.item[key],value);
  }
});
test('disabled P2P prevents adding exports and forwards', async () => {
  const app = setup(); const value = detail(); value.snapshot.configuration.p2p_enabled = false;
  app.renderManaged('node',value); app.nodes.get('managed-kind').value = 'export'; app.nodes.get('managed-kind').change();
  assert.equal(app.nodes.get('managed-submit').disabled,true);
  await app.nodes.get('managed-form').submit({preventDefault() {}});
  assert.equal(app.posts.length,0);
});
test('stale response after selecting another client is ignored', async () => {
  const app = setup(); let resolve;
  app.ctx.fetch = () => new Promise(done => {resolve = done;});
  const pending = app.refreshManaged('node');
  app.location.hash = '#client/other'; app.renderManaged('other',{snapshot:null});
  resolve({ok:true,json:async () => detail()}); await pending;
  assert.equal(app.state.managed.name,'other');
  assert.equal(app.state.managed.value.snapshot,null);
});
test('fetch failure disables writes and displays unavailability', async () => {
  const app = setup(); app.renderManaged('node',detail());
  app.ctx.fetch = async () => ({ok:false,status:503}); await app.refreshManaged('node');
  assert.match(app.nodes.get('managed-status').textContent,/不可用/);
  assert.equal(app.nodes.get('managed-submit').disabled,true);
});
test('approval labels and UIDs render as text while decisions use request IDs', async () => {
  const app = setup();
  const items = ['one', 'two'].map(id => ({request_id: id, client_id: `route-${id}`, display_name: '<script>same</script>', uid: `uid-${id}`, fingerprint: 'verified-key', created_at: 1}));
  app.ctx.fetch = async () => ({ok: true, json: async () => ({items})});
  await app.refreshApprovals(true);
  const rows = app.nodes.get('approval-list').children;
  assert.equal(rows.length, 2);
  for (const [index, row] of rows.entries()) {
    assert.ok(content(row).includes('<script>same</script>'));
    assert.ok(content(row).includes(items[index].uid));
    assert.ok(content(row).includes('连接后上报'));
    app.ctx.fetch = async (path) => { app.posts.push({path}); return {ok: true, json: async () => ({})}; };
    await row.children.at(-1).children[0].click();
    assert.equal(app.posts.at(-1).path, `/api/v1/registration-requests/${items[index].request_id}`);
  }
});
