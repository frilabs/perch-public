import { runInNewContext } from 'node:vm';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { sessionPage } from '../src/microsoft/sessionPage.js';

beforeEach(() => { vi.useFakeTimers(); });
afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); });
function fixture(latency = 50, responseStatus: (path: string) => number = () => 200) {
  const elements = new Map<string, any>();
  const calls: Array<{ path: string; data: any }> = [];
  let inFlight = 0, maximumInFlight = 0;
  const element = (id: string) => {
    if (!elements.has(id)) elements.set(id, { addEventListener() {}, focus() {}, removeAttribute() {} });
    return elements.get(id);
  };
  runInNewContext(sessionPage('test').match(/<script nonce="test">([\s\S]*?)<\/script>/)![1]!, {
    document: { getElementById: element, querySelectorAll: () => [] }, location: { hash: '' }, history: { replaceState() {} },
    Date, setTimeout, clearTimeout, setInterval,
    fetch: async (path: string, options: any) => {
      calls.push({ path, data: options.body ? JSON.parse(options.body) : undefined });
      maximumInFlight = Math.max(maximumInFlight, ++inFlight);
      await new Promise(resolve => setTimeout(resolve, latency));
      inFlight--;
      const status = responseStatus(path);
      return { ok: status === 200, status, json: async () => ({ image: 'AA==', host: 'login.microsoftonline.com', expires: Date.now() + 900_000 }) };
    },
  });
  return { calls, element, maximumInFlight: () => maximumInFlight,
    press(key: string) { element('screen').onkeydown({ key, metaKey: false, ctrlKey: false, preventDefault() {}, getModifierState: () => false }); },
  };
}

it('batches adjacent text without moving it across Tab or other actions', async () => {
  const f = fixture(); await vi.advanceTimersByTimeAsync(100);
  f.press('a'); f.press('b'); f.press('c'); f.press('Tab'); f.press('d');
  await vi.advanceTimersByTimeAsync(2000);
  expect(f.calls.filter(c => c.path === '/action').map(c => c.data)).toEqual([
    { type: 'text', text: 'abc' }, { type: 'key', key: 'Tab', shift: undefined }, { type: 'text', text: 'd' },
  ]);
});

it('refreshes the screen while more input is queued', async () => {
  const f = fixture(100); await vi.advanceTimersByTimeAsync(250); f.calls.length = 0;
  for (let n = 0; n < 20; n++) f.press('ArrowRight');
  await vi.advanceTimersByTimeAsync(700);
  expect(f.calls.some(c => c.path === '/state')).toBe(true);
  expect(f.calls.filter(c => c.path === '/action').length).toBeLessThan(20);
});

it('waits for an in-flight screenshot before dispatching input', async () => {
  const f = fixture(200); f.press('a');
  await vi.advanceTimersByTimeAsync(1000);
  expect(f.maximumInFlight()).toBe(1);
});

it('drains queued input before finishing and refuses new input during close', async () => {
  const f = fixture(); await vi.advanceTimersByTimeAsync(100);
  f.press('a'); f.press('Tab'); f.press('b');
  const finished = f.element('finish').onclick(); f.press('c');
  await vi.advanceTimersByTimeAsync(2000); await finished;
  expect(f.calls.filter(c => c.path === '/action').map(c => c.data.text ?? c.data.key)).toEqual(['a', 'Tab', 'b']);
  const finishAt = f.calls.findIndex(c => c.path === '/finish');
  expect(finishAt).toBeGreaterThan(f.calls.findLastIndex(c => c.path === '/action'));
});

it('stays below the server request limit during sustained fast typing', async () => {
  const f = fixture(5); await vi.advanceTimersByTimeAsync(20); f.calls.length = 0;
  const typing = setInterval(() => f.press('a'), 10);
  await vi.advanceTimersByTimeAsync(60_000); clearInterval(typing);
  expect(f.calls.length).toBeLessThan(550);
  expect(f.calls.filter(c => c.path === '/state').length).toBeGreaterThan(100);
});

it('never replays accepted input when the following screenshot is busy', async () => {
  let states = 0;
  const f = fixture(50, path => path === '/state' && ++states === 2 ? 409 : 200);
  await vi.advanceTimersByTimeAsync(100); f.press('a');
  await vi.advanceTimersByTimeAsync(2000);
  expect(f.calls.filter(c => c.path === '/action')).toHaveLength(1);
});

it('splits long typing batches at the server limit without losing characters', async () => {
  const f = fixture(5); await vi.advanceTimersByTimeAsync(20);
  f.element('screen').onpaste({ preventDefault() {}, clipboardData: { getData: () => 'a'.repeat(4096) } });
  f.press('b'); f.press('c');
  await vi.advanceTimersByTimeAsync(1000);
  const text = f.calls.filter(c => c.path === '/action').map(c => c.data.text);
  expect(text.every(t => t.length <= 4096)).toBe(true);
  expect(text.join('')).toBe('a'.repeat(4096) + 'bc');
});

it('retries explicitly rejected busy input but sends no duplicate after acceptance', async () => {
  let actions = 0;
  const f = fixture(10, path => path === '/action' && ++actions === 1 ? 409 : 200);
  await vi.advanceTimersByTimeAsync(20); f.press('a');
  await vi.advanceTimersByTimeAsync(1000);
  expect(f.calls.filter(c => c.path === '/action').map(c => c.data.text)).toEqual(['a', 'a']);
});

it('keeps typing usable after an idle screenshot fails while text is queued', async () => {
  let states = 0;
  const f = fixture(30, path => path === '/state' && ++states === 1 ? 502 : 200);
  f.press('a'); await vi.advanceTimersByTimeAsync(80); f.press('b');
  await vi.advanceTimersByTimeAsync(1000);
  expect(f.calls.filter(c => c.path === '/action').map(c => c.data.text).join('')).toBe('ab');
});
