import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { ANCHOR, VOICE_PROFILE, redirectPatch, say, speak, voiceViolations } from '../src/persona.js';

describe('voice guard', () => {
  it.each([
    'Sorry about that.',
    'I apologize for the delay.',
    'My bad.',
    'That was my mistake',
    'Please forgive me',
    'Unfortunately the build failed',
    'I hope this helps!',
    'Feel free to retry',
    'Happy to help',
    "I'm afraid that is not possible",
  ])('flags %s', (text) => {
    expect(voiceViolations(text).length).toBeGreaterThan(0);
  });

  it('passes clipped command language', () => {
    expect(voiceViolations('Proof rejected. Regenerate evidence. Attempt 2 of 3.')).toEqual([]);
  });
});

describe('speak()', () => {
  it('returns clean text untouched', () => {
    expect(speak('Execute exactly.')).toBe('Execute exactly.');
  });
  it('replaces offending sentences with the Deductive Anchor, once', () => {
    const out = speak('Sorry for the confusion. Use the staging database. I apologize again.');
    expect(out.startsWith(ANCHOR)).toBe(true);
    expect(out).toContain('Use the staging database.');
    expect(voiceViolations(out)).toEqual([]);
    expect(out.split(ANCHOR)).toHaveLength(2);
  });
  it('does not stack the anchor on text that already carries it', () => {
    const out = speak(`${ANCHOR} Sorry. Proceed.`);
    expect(out.split(ANCHOR)).toHaveLength(2);
    expect(out).toContain('Proceed.');
  });
});

describe('templates', () => {
  const samples = [
    say.directive(1, 3),
    say.hold('awaiting_operator'),
    say.hold('quarantined'),
    say.hold('completed'),
    say.hold('terminated'),
    say.accepted(),
    say.missionComplete(),
    say.rejected(2, 2, 3),
    say.quarantined(),
    say.cleared(),
    say.denied(),
    say.staged(),
    say.authorized(),
    say.killed(),
    say.redirected('Use the replica.'),
    say.throttled(12),
    say.creditsExhausted(),
    say.leaseInvalid(),
    say.unauthenticated(),
    say.forbidden(),
    say.notFound(),
    say.invalid('Missing field.'),
    say.conflict('Already decided.'),
    redirectPatch({
      attempt: 2,
      max: 3,
      failures: [
        { type: 'exit_code', hidden: false, reason: 'Required exit code 0; received 1.', fix: 'Fix it.' },
        { type: 'regex', hidden: true, reason: 'secret', fix: 'secret' },
      ],
      nonce: 'nonce_x',
      operatorPatch: 'Sorry, use the other path.',
    }),
  ];
  it('no template apologizes or pads', () => {
    for (const s of samples) expect(voiceViolations(s), s).toEqual([]);
  });
});

describe('deductive anchoring', () => {
  it('redirects carry the anchor sentence verbatim', () => {
    expect(say.redirected('Use the replica.')).toBe(`${ANCHOR} Use the replica.`);
  });
  it('a redirect never concedes fault, even if the operator note does', () => {
    const out = say.redirected('My bad, wrong table. Query orders instead.');
    expect(voiceViolations(out)).toEqual([]);
    expect(out).toContain('Query orders instead.');
  });
});

describe('redirect patch', () => {
  it('hides the details of hidden checks', () => {
    const patch = redirectPatch({
      attempt: 2,
      max: 3,
      failures: [{ type: 'regex', hidden: true, reason: 'pattern /s3cr3t/ not found', fix: 'include s3cr3t' }],
    });
    expect(patch).not.toContain('s3cr3t');
    expect(patch).toContain('[hidden]');
  });
});

describe('COMMANDER_SOUL.md stays aligned with the code', () => {
  const soul = readFileSync(new URL('../COMMANDER_SOUL.md', import.meta.url), 'utf8');
  it('contains the exact Deductive Anchor sentence', () => {
    expect(soul).toContain(ANCHOR);
  });
  it('names the voice profile the code emits', () => {
    expect(soul).toContain(VOICE_PROFILE.class);
    expect(soul).toContain(VOICE_PROFILE.alternate);
  });
  it('documents that the audit ledger is not voiced', () => {
    expect(soul).toMatch(/ledger/i);
  });
});
