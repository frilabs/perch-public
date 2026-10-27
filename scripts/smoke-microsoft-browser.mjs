// Opt-in Linux smoke: synthetic responses only, plus public Microsoft OIDC metadata over HTTPS.
// Never opens the operator profile/store or uses a Microsoft account. All temporary profiles are removed.
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';
const base = path.resolve(process.argv[2] ?? '.');
const { launchSessionBrowser, openSessionProfile, findSessionBrowser, BrowserPipe } = await import(pathToFileURL(path.join(base, 'dist/microsoft/sessionBrowser.js')));
// Optional synthetic-only target diagnostics; never log URLs, headers or protocol payloads.
if (process.env.PERCH_SMOKE_TRACE === '1') {
  const original = BrowserPipe.prototype.call;
  let lastTargets;
  BrowserPipe.prototype.call = async function(method, params, sessionId) {
    try {
      const result = await original.call(this, method, params, sessionId);
      if (method === 'Target.getTargets') {
        const targets = JSON.stringify(result.targetInfos.map(info => ({ id: info.targetId, type: info.type, attached: info.attached, subtype: info.subtype, ...(info.type === 'browser_ui' ? { scheme: (() => { try { return new URL(info.url).protocol; } catch { return 'unavailable'; } })() } : {}) })));
        if (targets !== lastTargets) { console.error('synthetic targets:', targets); lastTargets = targets; }
      }
      if (method === 'Target.closeTarget') console.error('synthetic close:', params.targetId, result.success);
      return result;
    } catch (error) { console.error('synthetic CDP failure:', method, sessionId, method === 'Runtime.evaluate' ? (String(params?.expression).includes('PerchDisabledChannel') ? 'channel-lockdown' : 'other-evaluation') : ''); throw error; }
  };
}
const { BrowserSessionTransport } = await import(pathToFileURL(path.join(base, 'dist/microsoft/session/browserTransport.js')));
const { outlookOperations } = await import(pathToFileURL(path.join(base, 'dist/microsoft/session/outlook.js')));
const root = await mkdtemp(path.join(tmpdir(), 'perch-ms-synthetic-'));
const profile = await openSessionProfile(root, 'Synthetic');
let browser, transport, off, chromeVersion;
let calls = 0, mutations = 0, guards = 0, mailSession;
const phase = name => { if (process.env.PERCH_SMOKE_TRACE === '1') console.error('synthetic phase:', name); };
const identity = { tenantId: '11111111-1111-4111-8111-111111111111', objectId: '22222222-2222-4222-8222-222222222222', kind: 'organization' };
const token = [{ alg: 'RS256' }, { tid: identity.tenantId, oid: identity.objectId, exp: Math.floor(Date.now() / 1000) + 3600, aud: 'https://outlook.office.com', upn: 'synthetic@example.test' }, 'synthetic-signature'].map((x, i) => i === 2 ? x : Buffer.from(JSON.stringify(x)).toString('base64url')).join('.');
const channels = `function channelChecks(){globalThis.channelDiagnostics=[];return ['WebSocket','WebSocketStream','WebTransport'].map(name=>{try{new globalThis[name](name==='WebTransport'?'https://worker.invalid/':'wss://worker.invalid/socket');channelDiagnostics.push(name+':constructed');return false}catch(error){channelDiagnostics.push(name+':'+error.name);return error.name==='SecurityError'}})}`;
const registration = `async function registrationCheck(){try{await navigator.serviceWorker.register('/perch-synthetic-worker.js');return false}catch(e){return e.name==='SecurityError'}}`;
const childPage = (kind) => `<!doctype html><title>Synthetic ${kind}</title><script>${channels};${registration};(async()=>{const result={registration:await registrationCheck(),kind:${JSON.stringify(kind)},channels:channelChecks(),diagnostics:globalThis.channelDiagnostics,post:await fetch('/owa/service.svc?action=${kind}',{method:'POST'}).then(()=>false,()=>true)};(opener||parent).postMessage({perchSmoke:result},'https://outlook.office.com')})();</script>`;
async function evaluate(expression, sessionId = mailSession, options = {}) {
  const result = await browser.protocol.call('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true, ...options }, sessionId);
  assert.equal(result.exceptionDetails, undefined, 'Synthetic evaluation failed');
  return result.result?.value;
}
async function waitFor(expression, description, sessionId = mailSession) {
  for (let attempt = 0; attempt < 60; attempt++) {
    const result = await evaluate(expression, sessionId);
    if (result) return result;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.fail(`Timed out waiting for ${description}`);
}
try {
  browser = await launchSessionBrowser(await findSessionBrowser(process.env), profile.path, 'about:blank', { workerMode: true, extraHosts: [] });
  chromeVersion = (await browser.protocol.call('Browser.getVersion')).product;
  // Instrument the exact object used by the launcher's WeakMap-backed guard manager.
  // A wrapper object would create a second auto-attachment owner and invalidate the proof.
  const protocol = browser.protocol, originalCall = protocol.call.bind(protocol);
  const paused = new Map(), deniedPosts = new Set(), attachedTypes = new Set(), workerNetworkFailures = [], escapedPosts = [];
  const workerRequests = new Set();
  let workerRequestSeen = false;
  off = protocol.onEvent(event => {
    if (event.method === 'Fetch.requestPaused') paused.set(event.params.requestId, { ...event.params, sessionId: event.sessionId });
    if (event.method === 'Target.attachedToTarget') {
      attachedTypes.add(event.params.targetInfo.type);
      if (process.env.PERCH_SMOKE_TRACE === '1') console.error('synthetic attached:', event.params.targetInfo.type, event.params.sessionId, 'waitingForDebugger:', event.params.waitingForDebugger);
    }
    if (event.method === 'Network.requestWillBeSent' && event.params.request?.url === 'https://worker.invalid/guard') { workerRequestSeen = true; workerRequests.add(`${event.sessionId}:${event.params.requestId}`); }
    if (event.method === 'Network.loadingFailed' && workerRequests.has(`${event.sessionId}:${event.params.requestId}`) && event.params.blockedReason === 'inspector') workerNetworkFailures.push(event.params.blockedReason);
  });
  protocol.call = async (method, params = {}, sessionId) => {
    // Guard listeners run before this observer in BrowserPipe.receive; yield until
    // all synchronous listeners have recorded the paused request before reading it.
    if (method === 'Fetch.failRequest' || method === 'Fetch.continueRequest') await Promise.resolve();
    const state = paused.get(params.requestId);
    if (method === 'Fetch.failRequest' && state?.request.method === 'POST') deniedPosts.add(new URL(state.request.url).searchParams.get('action'));
    if (method === 'Fetch.continueRequest') {
      assert.ok(state, 'Every continued request must have a recorded paused event');
      const req = state.request, url = new URL(params.url ?? req.url);
      calls++;
      if (['outlook.office.com', 'teams.microsoft.com', 'outlook.cloud.microsoft'].includes(url.hostname)) {
        let body = {}, type = 'application/json';
        if (url.pathname === '/mail/') {
          mailSession = sessionId; type = 'text/html';
          body = `<!doctype html><title>Synthetic Perch test</title><script>${channels};globalThis.smokeResults={};addEventListener('message',event=>{if(['https://teams.microsoft.com','https://outlook.cloud.microsoft'].includes(event.origin)&&event.data?.perchSmoke)smokeResults[event.data.perchSmoke.kind]=event.data.perchSmoke});fetch('/owa/service.svc',{headers:{Authorization:${JSON.stringify('Bearer ' + token)}}}).catch(()=>{});fetch('/owa/service.svc?action=main',{method:'POST'}).catch(()=>{});</script>`;
        } else if (url.pathname === '/guard-frame') { type = 'text/html'; body = childPage('iframe'); }
        else if (url.pathname === '/guard-popup') { type = 'text/html'; body = childPage('popup'); }
        else if (url.pathname === '/api/v2.0/me') body = { Id: 'mailbox-synthetic', EmailAddress: 'synthetic@example.test', DisplayName: 'Synthetic' };
        else if (req.method === 'PATCH') {
          assert.match(req.headers['Content-Type'] ?? req.headers['content-type'] ?? '', /application\/json/);
          assert.equal(url.searchParams.has('__perch_request'), false);
          mutations++;
        }
        // Any unexpected background write fails the smoke before it can hit the network.
        if (req.method === 'POST') escapedPosts.push(url.searchParams.get('action'));
        assert.notEqual(req.method, 'POST', 'An unrequested background POST escaped its target guard');
        return originalCall('Fetch.fulfillRequest', { requestId: params.requestId, responseCode: 200, responseHeaders: [{ name: 'Content-Type', value: type }, { name: 'Access-Control-Allow-Origin', value: '*' }, { name: 'Access-Control-Allow-Headers', value: '*' }, { name: 'Access-Control-Allow-Methods', value: 'GET,POST,PATCH,OPTIONS' }], body: Buffer.from(typeof body === 'string' ? body : JSON.stringify(body)).toString('base64') }, sessionId);
      }
    }
    return originalCall(method, params, sessionId);
  };
  phase('transport-open');
  transport = new BrowserSessionTransport(protocol, [], identity, { waitMs: 15000, beforeMutation: async () => { guards++; } });
  await transport.open('mail');
  const ctx = { request: request => transport.request(request), identity, sites: [] };
  phase('profile-read');
  const me = await outlookOperations['mail.profile'].run(ctx, {});
  assert.equal(me.email, 'synthetic@example.test');
  phase('authorized-mutation');
  await outlookOperations['mail.mark'].run(ctx, { messageId: 'test-message', read: true });
  assert.equal(mutations, 1); assert.equal(guards, 1); assert.deepEqual(transport.identity, identity);
  phase('page-channels');
  assert.deepEqual(await evaluate('channelChecks()'), [true, true, true]);
  assert.equal(await evaluate(`(async()=>{${registration};return registrationCheck()})()`),true,'main service worker registration');
  phase('iframe-popup');
  await evaluate(`(()=>{const frame=document.createElement('iframe');frame.src='https://teams.microsoft.com/guard-frame';document.body.append(frame);return !!window.open('https://outlook.cloud.microsoft/guard-popup','synthetic-popup')})()`, mailSession, { userGesture: true }).then(opened => assert.equal(opened, true, 'Synthetic popup must open'));
  const childResults = await waitFor('smokeResults.iframe && smokeResults.popup && smokeResults', 'cross-origin iframe and popup results');
  if (process.env.PERCH_SMOKE_TRACE === '1') console.error('synthetic child results:', JSON.stringify(childResults));
  for (const kind of ['iframe', 'popup']) { assert.equal(childResults[kind].registration,true,`${kind} service worker registration`); assert.equal(childResults[kind].post, true, `${kind} POST`); assert.deepEqual(childResults[kind].channels, [true, true, true], `${kind} channel constructors`); }
  phase('worker');
  const workerScript = `${channels};(async()=>postMessage({channels:channelChecks(),diagnostics:globalThis.channelDiagnostics,post:await fetch('https://worker.invalid/guard',{method:'POST'}).then(()=>false,()=>true)}))()`;
  await evaluate(`(()=>{globalThis.workerResult=null;const worker=new Worker(URL.createObjectURL(new Blob([${JSON.stringify(workerScript)}],{type:'text/javascript'})));globalThis.smokeWorker=worker;worker.onmessage=event=>{workerResult=event.data};return true})()`);
  const workerResult = await waitFor('workerResult', 'dedicated worker restrictions');
  assert.deepEqual(workerResult.channels, [true, true, true]); assert.equal(workerResult.post, true);
  assert.equal(workerRequestSeen, true); assert.ok(workerNetworkFailures.length > 0, 'Worker network must be blocked by CDP, not merely DNS or CORS');
  assert.deepEqual(escapedPosts, [], 'No background POST may be continued by a guard');
  assert.ok(attachedTypes.has('iframe')); assert.ok(attachedTypes.has('worker'));
  for (const kind of ['main', 'iframe', 'popup']) assert.ok(deniedPosts.has(kind), `${kind} POST must be denied`);
  assert.equal(attachedTypes.has('service_worker'),false,'No service worker should have been created');
  await outlookOperations['mail.profile'].run(ctx, {});
  phase('unknown-host');
  const denial = await evaluate("fetch('https://example.com/').then(()=>false,()=>true)");
  assert.equal(denial, true); assert.ok(browser.blockedHosts().includes('example.com'));
  phase('public-metadata');
  await protocol.call('Page.navigate', { url: 'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration' }, browser.mainSessionId);
  await waitFor("(()=>{try{return new URL(JSON.parse(document.body.innerText).token_endpoint).hostname==='login.microsoftonline.com'}catch{return false}})()", 'public Microsoft OIDC metadata', browser.mainSessionId);
  console.log(JSON.stringify({ chromeVersion, syntheticOnly: true, browserSandbox: true, privateCdp: true, workerMode: true, requests: calls, mutations, grantGuards: guards, identityVerifiedAgainstSyntheticResponse: true, unknownHostBlocked: true, allowedMicrosoftHttps: true, backgroundWritesBlocked: [...deniedPosts].sort(), crossOriginIframe: true, popup: true, pageAndChildChannelsBlocked: true, workerChannelsBlocked: true, workerNetworkBlockedByInspector: true, serviceWorkerRegistrationBlocked:true }));
} finally {
  off?.(); transport?.close(); await browser?.close(); await profile.release(); await rm(root, { recursive: true, force: true });
}
