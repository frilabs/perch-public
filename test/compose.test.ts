// Outbound message validation and MIME building (local only, no network).
import { describe, expect, it } from 'vitest';
import { buildMime, MAX_ATTACHMENT_TOTAL_BYTES, validateOutgoing, type ComposeInput } from '../src/mail/compose.js';

const base: ComposeInput = {
  to: ['Dummy Recipient <rcpt@example.test>'],
  subject: 'Hello',
  text: 'Body line',
};

const mime = async (input: ComposeInput, keepBcc = true) =>
  (await buildMime(validateOutgoing(input, 'sender@example.test'), { keepBcc })).toString('utf8');

describe('validateOutgoing', () => {
  it('fills From from the chosen account and accepts a matching explicit from', () => {
    expect(validateOutgoing(base, 'Sender@Example.test').from).toBe('Sender@Example.test');
    expect(validateOutgoing({ ...base, from: 'sender@example.test' }, 'Sender@Example.test').from).toBe('Sender@Example.test');
  });

  it('refuses a From that differs from the chosen account', () => {
    expect(() => validateOutgoing({ ...base, from: 'someone.else@example.test' }, 'sender@example.test')).toThrow(/must match/i);
  });

  it.each([
    ['subject CRLF', { subject: 'Hi\r\nBcc: victim@example.test' }],
    ['subject LF', { subject: 'Hi\nX-Evil: 1' }],
    ['address CRLF', { to: ['rcpt@example.test\r\nBcc: victim@example.test'] }],
    ['two addresses in one field', { to: ['a@example.test, b@example.test'] }],
    ['display name with angle', { to: ['Evil <x> <a@example.test>'] }],
    ['in-reply-to CRLF', { inReplyTo: '<a@example.test>\r\nBcc: v@example.test' }],
    ['bad references', { references: ['not-a-message-id'] }],
    ['filename CRLF', { attachments: [{ filename: 'a\r\n.txt', contentBase64: 'aGk=' }] }],
    ['content type injection', { attachments: [{ filename: 'a.txt', contentType: 'text/plain\r\nX: y', contentBase64: 'aGk=' }] }],
  ])('denies header injection: %s', (_name, patch) => {
    expect(() => validateOutgoing({ ...base, ...(patch as Partial<ComposeInput>) }, 'sender@example.test')).toThrow();
  });

  it('requires at least one recipient and bounds the recipient count', () => {
    expect(() => validateOutgoing({ ...base, to: [] }, 'sender@example.test')).toThrow(/recipient/i);
    const many = Array.from({ length: 101 }, (_, i) => `r${i}@example.test`);
    expect(() => validateOutgoing({ ...base, to: many }, 'sender@example.test')).toThrow(/recipients/i);
  });

  it('accepts only inline base64 attachments within the size bound (no paths or URLs)', () => {
    expect(() =>
      validateOutgoing({ ...base, attachments: [{ filename: 'a.txt', contentBase64: 'not base64!!' }] }, 'sender@example.test'),
    ).toThrow(/base64/i);
    const big = Buffer.alloc(MAX_ATTACHMENT_TOTAL_BYTES + 1).toString('base64');
    expect(() => validateOutgoing({ ...base, attachments: [{ filename: 'a.bin', contentBase64: big }] }, 'sender@example.test')).toThrow(
      /too large/i,
    );
    const withPath = { ...base, attachments: [{ filename: 'a.txt', contentBase64: 'aGk=', path: '/etc/passwd' }] } as unknown as ComposeInput;
    expect(() => validateOutgoing(withPath, 'sender@example.test')).toThrow(/unsupported attachment field/i);
    const withHref = { ...base, attachments: [{ filename: 'a.txt', href: 'http://169.254.169.254/' }] } as unknown as ComposeInput;
    expect(() => validateOutgoing(withHref, 'sender@example.test')).toThrow(/unsupported attachment field/i);
  });
});

describe('buildMime', () => {
  it('emits From, threading headers and a base64 attachment', async () => {
    const out = await mime({
      ...base,
      inReplyTo: '<orig-1@example.test>',
      references: ['<root@example.test>', '<orig-1@example.test>'],
      attachments: [{ filename: 'note.txt', contentType: 'text/plain', contentBase64: Buffer.from('attached').toString('base64') }],
    });
    expect(out).toMatch(/^From: sender@example\.test\r?$/m);
    expect(out).toMatch(/^In-Reply-To: <orig-1@example\.test>\r?$/m);
    expect(out).toMatch(/^References: <root@example\.test> <orig-1@example\.test>\r?$/m);
    expect(out).toContain('filename=note.txt');
    expect(out).toContain(Buffer.from('attached').toString('base64'));
    expect(out).toMatch(/^Message-ID: <[^>]+@example\.test>\r?$/m);
  });

  it('keeps Bcc only when asked (API drafts/sends need it, SMTP uses the envelope)', async () => {
    const withBcc = { ...base, bcc: ['hidden@example.test'] };
    expect(await mime(withBcc, true)).toMatch(/^Bcc: hidden@example\.test/m);
    expect(await mime(withBcc, false)).not.toMatch(/^Bcc:/m);
  });

  it('encodes non-ASCII subjects instead of emitting raw header bytes', async () => {
    const out = await mime({ ...base, subject: 'Grüße aus Wien' });
    expect(out).toMatch(/^Subject: =\?UTF-8\?/m);
  });
});
