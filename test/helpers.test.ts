import { describe, expect, it } from 'vitest';
import { analyzeRules, draftSafeReply, educationTip } from '../src/index.js';

describe('draftSafeReply', () => {
  it('returns category-specific replies in es and en', () => {
    const r = analyzeRules({ text: 'Hola mamá, este es mi nuevo número, me podés transferir C$2,000?' });
    expect(draftSafeReply(r, 'es')).toMatch(/llamar/);
    expect(draftSafeReply(r, 'en')).toMatch(/call/);
  });
  it('accepts a category directly and defaults to Spanish', () => {
    expect(draftSafeReply('bank_impersonation')).toMatch(/banco/);
    expect(draftSafeReply('phishing_link', 'en')).toMatch(/official/);
  });
  it('uses a neutral reply for safe results', () => {
    expect(draftSafeReply(analyzeRules({ text: 'Hola' }), 'en')).toMatch(/Thanks/);
  });
});

describe('educationTip', () => {
  it('returns tips per category and rotates with seed', () => {
    const a = educationTip('bank_impersonation', 'es', 0);
    const b = educationTip('bank_impersonation', 'es', 1);
    expect(a).not.toBe(b);
    expect(educationTip('fake_job', 'en')).toMatch(/jobs/);
    expect(educationTip()).toBeTruthy();
  });
});
