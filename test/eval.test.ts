import { describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import { evaluate, loadSamples } from '../scripts/eval.js';

describe('dataset evaluation (rules only)', () => {
  const samples = loadSamples(fileURLToPath(new URL('../data/samples.jsonl', import.meta.url)));
  it('has ~60 labeled synthetic samples covering all classes', () => {
    expect(samples.length).toBeGreaterThanOrEqual(55);
    for (const l of ['scam', 'suspicious', 'safe']) expect(samples.some((s) => s.label === l)).toBe(true);
  });
  it('reaches >= 90% accuracy', () => {
    expect(evaluate(samples).accuracy).toBeGreaterThanOrEqual(0.9);
  });
  it('never labels a legitimate message as scam', () => {
    expect(evaluate(samples).matrix.safe.scam).toBe(0);
  });
});
