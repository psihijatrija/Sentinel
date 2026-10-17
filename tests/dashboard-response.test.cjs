const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// Decode the dashboard's verbatim C# string to exercise the authored renderer.
const htmlSource = fs.readFileSync(path.join(__dirname, '../src/Sentinel.Agent/DashboardHtml.cs'), 'utf8')
  .replaceAll('""', '"').replaceAll('{{', '{').replaceAll('}}', '}');
function sourceOf(name) {
  const match = htmlSource.match(new RegExp('function ' + name + '\\([^)]*\\) \\{[\\s\\S]*?\n\\}'));
  assert.ok(match, 'Missing dashboard function ' + name);
  return match[0];
}
function render(type, data) {
  const container = { innerHTML: '' };
  const document = {
    getElementById: () => container,
    createTextNode: text => text,
    createElement: () => ({
      innerHTML: '',
      appendChild(text) {
        this.innerHTML = text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
      }
    })
  };
  const context = vm.createContext({ document });
  vm.runInContext(sourceOf('esc') + '\n' + sourceOf('renderEvents'), context);
  context.renderEvents([{ type, data: JSON.stringify({ type, data }) }], 'events');
  return container.innerHTML;
}

test('dashboard JavaScript remains syntactically valid', () => {
  const scripts = [...htmlSource.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  assert.ok(scripts.length > 0);
  for (const script of scripts) new vm.Script(script[1]);
});
for (const status of ['Refused', 'Attempted', 'Failed', 'PartiallyCompleted']) {
  test(status + ' response never receives a success checkmark', () => {
    const html = render('response', {
      ActionTaken: 'KILL', Reason: 'Fixture', Execution: { Status: status, Effects: [] }
    });
    assert.match(html, new RegExp('Response: ' + status));
    assert.doesNotMatch(html, /\u2713/);
  });
}
test('only verified effects receive a checkmark', () => {
  assert.match(render('response_result', { Status: 'Verified', VerifiesRequestedAction: true, Effects: [] }), /\u2713/);
});
test('a verified effect label without a completed requested-action receipt is insufficient', () => {
  assert.doesNotMatch(render('response_result', { Status: 'Verified', VerifiesRequestedAction: false, Effects: [] }), /\u2713/);
});
test('legacy action labels cannot imply verified success', () => {
  const html = render('response', { ActionTaken: 'KILL', Reason: 'Legacy fixture' });
  assert.match(html, /Unverified legacy record/);
  assert.doesNotMatch(html, /\u2713/);
});
test('outcome details remain escaped when rendered', () => {
  const html = render('response_result', {
    Status: 'Failed', Reason: '<img src=x onerror=alert(1)>',
    Effects: [{ Action: 'ProcessTree', Status: 'Failed', Detail: '<script>bad()</script>' }]
  });
  assert.match(html, /&lt;img/);
  assert.match(html, /&lt;script/);
  assert.doesNotMatch(html, /<img|<script/);
});

test('unverified firewall policy never gets an active dashboard badge', () => {
  const elements = {};
  const context = vm.createContext({
    document: { getElementById(id) { return elements[id] ||= {}; } },
    apiCall(endpoint, options, callback) {
      callback(endpoint === '/api/status'
        ? { ok: true, version: '3.2.3', serviceRunning: true, firewallPolicyCompliant: false }
        : { ok: false });
    }
  });
  vm.runInContext(sourceOf('loadStatus'), context);
  context.loadStatus();
  assert.equal(elements['status-text'].textContent, 'Firewall policy needs attention');
  assert.equal(elements['ov-status'].textContent, 'Needs attention');
});

test('verified offline firewall policy can display active protection', () => {
  const elements = {};
  const context = vm.createContext({
    document: { getElementById(id) { return elements[id] ||= {}; } },
    apiCall(endpoint, options, callback) {
      callback(endpoint === '/api/status'
        ? { ok: true, version: '3.2.3', serviceRunning: true, firewallPolicyCompliant: true }
        : { ok: false });
    }
  });
  vm.runInContext(sourceOf('loadStatus'), context);
  context.loadStatus();
  assert.equal(elements['status-text'].textContent, 'Offline Protection Active');
  assert.equal(elements['ov-status'].className, 'card-value success');
});
