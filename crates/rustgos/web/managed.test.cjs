const assert = require('node:assert/strict');
const { test } = require('node:test');
const { readFileSync } = require('node:fs');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
function setup() {
  const nodes = new Map();
  const element = () => ({ children: [], dataset: {}, value: '', addEventListener(e, f) { this[e] = f; }, append(...a) { this.children.push(...a); }, replaceChildren(...a) { this.children = a; }, reset() {}, });
  for (const id of ['managed-status', 'managed-operation-status', 'managed-rows', 'managed-form', 'managed-fields', 'managed-kind', 'managed-submit']) nodes.set(id, element());
  nodes.get('managed-kind').value = 'tunnel';
  const location = { hash: '#client/node' };
  const posts = [];
  const ctx = { crypto: webcrypto, location, AbortController, URLSearchParams, clearTimeout, window: { location, addEventListener() {} }, document: { hidden: true, getElementById: id => nodes.get(id), querySelector: () => null, querySelectorAll: () => [], createElement: element, addEventListener() {} }, fetch: async (path, opts) => { posts.push({path, body: JSON.parse(opts.body)}); return {ok: true, json: async () => ({})}; } };
  const source = readFileSync(`${__dirname}/app.js`, 'utf8').replace(/\r\n/g, '\n').replace('  showRoute();\n  requestPoll();', '  globalThis.api = { state, renderManaged: typeof renderManaged === "function" ? renderManaged : undefined, mutateManaged: typeof mutateManaged === "function" ? mutateManaged : undefined, refreshManaged: typeof refreshManaged === "function" ? refreshManaged : undefined };');
  vm.runInNewContext(source, ctx);
  return { ...ctx.api, nodes, posts, location, ctx };
}
const detail = () => ({ online: true, supported: true, snapshot: {revision: 4, applied_revision: 4, configuration: {p2p_enabled: true, tunnels: [{name:'<tcp>',protocol:'tcp',local_addr:'127.0.0.1:80',remote_port:8080}],exports:[{name:'share',protocol:'udp',local_addr:'127.0.0.1:53',allowed_peers:[]}],forwards:[{name:'use',peer:'other',export:'share',listen_addr:'127.0.0.1:9000'}]},results:[{kind:'tunnel',name:'<tcp>',state:'ready'},{kind:'export',name:'share',state:'failed',error:'bind error'}]}});
const content = node => [node.textContent || '', ...node.children.map(content)].join(' ');
test('all kinds render safe names, addresses, ACL and actual results', () => {
  const app = setup(); app.renderManaged('node', detail());
  const output = content(app.nodes.get('managed-rows'));
  for (const value of ['<tcp>', '127.0.0.1:80', '8080', 'share', '所有已授权客户端', 'other', '127.0.0.1:9000', 'bind error', '等待']) assert.ok(output.includes(value), value);
  assert.equal(app.nodes.get('managed-rows').children.length, 3);
});
test('deletion carries exact name, kind and expected revision; duplicate submit suppressed', async () => {
  const app = setup(); app.renderManaged('node', detail());
  await Promise.all([app.mutateManaged({action:'delete',kind:'tunnel',name:'<tcp>'}), app.mutateManaged({action:'delete',kind:'tunnel',name:'<tcp>'})]);
  assert.equal(app.posts.length, 1);
  assert.equal(app.posts[0].body.expected_revision, 4);
  assert.equal(app.posts[0].body.name, '<tcp>');
  assert.equal(app.posts[0].body.kind, 'tunnel');
});
test('offline or stale report cannot appear ready; polling preserves input nodes', () => {
  const app = setup(); const value = detail(); app.renderManaged('node', value);
  const fields = app.nodes.get('managed-fields').children;
  value.online = false; value.snapshot.applied_revision = 3; app.renderManaged('node', value);
  assert.match(app.nodes.get('managed-status').textContent, /离线/);
  assert.ok(!content(app.nodes.get('managed-rows')).includes('已就绪'));
  assert.equal(app.nodes.get('managed-fields').children, fields);
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
    ['tunnel', {name:'web',protocol:'udp',local_addr:'127.0.0.1:80',remote_port:'8080'}, {remote_port:8080}],
    ['export', {name:'share',protocol:'tcp',local_addr:'127.0.0.1:80',allowed_peers:'one, two'}, {allowed_peers:['one','two']}],
    ['forward', {name:'use',peer:'other',export:'share',listen_addr:'127.0.0.1:9000'}, {peer:'other',export:'share'}],
  ]) {
    const app = setup(); app.renderManaged('node', detail());
    app.nodes.get('managed-kind').value = kind; app.nodes.get('managed-kind').change();
    for (const [key,value] of Object.entries(values)) app.state.managed.fields[key].value = value;
    await app.nodes.get('managed-form').submit({preventDefault() {}});
    assert.equal(app.posts[0].body.kind,kind);
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
