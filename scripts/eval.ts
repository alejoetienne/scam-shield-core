/**
 * Rules-only evaluation over data/samples.jsonl.
 * Usage: npm run eval [-- path/to/file.jsonl] [--verbose]
 */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeRules } from '../src/index.js';
import type { Verdict } from '../src/index.js';

interface Sample {
  id: string;
  label: Verdict;
  text: string;
  url?: string;
}

const LABELS: Verdict[] = ['scam', 'suspicious', 'safe'];

export function loadSamples(path: string): Sample[] {
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l) as Sample);
}

export function evaluate(samples: Sample[]) {
  const matrix: Record<Verdict, Record<Verdict, number>> = {
    scam: { scam: 0, suspicious: 0, safe: 0 },
    suspicious: { scam: 0, suspicious: 0, safe: 0 },
    safe: { scam: 0, suspicious: 0, safe: 0 },
  };
  const errors: { id: string; label: Verdict; predicted: Verdict; score: number; text: string; signals: string[] }[] = [];
  for (const s of samples) {
    const r = analyzeRules({ text: s.text, url: s.url });
    matrix[s.label][r.verdict]++;
    if (r.verdict !== s.label) {
      errors.push({ id: s.id, label: s.label, predicted: r.verdict, score: r.riskScore, text: s.text, signals: r.signals.map((x) => `${x.id}:${x.weight}`) });
    }
  }
  const correct = LABELS.reduce((n, l) => n + matrix[l][l], 0);
  const perClass = LABELS.map((l) => {
    const tp = matrix[l][l];
    const predicted = LABELS.reduce((n, a) => n + matrix[a][l], 0);
    const actual = LABELS.reduce((n, p) => n + matrix[l][p], 0);
    const precision = predicted ? tp / predicted : 0;
    const recall = actual ? tp / actual : 0;
    const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
    return { label: l, precision, recall, f1, support: actual };
  });
  return { accuracy: correct / samples.length, total: samples.length, correct, matrix, perClass, errors };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const args = process.argv.slice(2);
  const verbose = args.includes('--verbose');
  const here = dirname(fileURLToPath(import.meta.url));
  const file = args.find((a) => !a.startsWith('--')) ?? resolve(here, '../data/samples.jsonl');
  const res = evaluate(loadSamples(file));
  const pct = (x: number) => `${(x * 100).toFixed(1)}%`;
  console.log(`scam-shield-core eval (rules only) — ${file}`);
  console.log(`Accuracy: ${pct(res.accuracy)} (${res.correct}/${res.total})\n`);
  console.log('Per-class:');
  console.log('  class        precision  recall   f1      support');
  for (const c of res.perClass) {
    console.log(`  ${c.label.padEnd(12)} ${pct(c.precision).padStart(8)}  ${pct(c.recall).padStart(7)}  ${pct(c.f1).padStart(6)}  ${String(c.support).padStart(5)}`);
  }
  console.log('\nConfusion matrix (rows = actual, cols = predicted):');
  console.log(`  ${''.padEnd(12)}${LABELS.map((l) => l.padStart(12)).join('')}`);
  for (const a of LABELS) {
    console.log(`  ${a.padEnd(12)}${LABELS.map((p) => String(res.matrix[a][p]).padStart(12)).join('')}`);
  }
  if (res.errors.length) {
    console.log(`\nMisclassified (${res.errors.length}):`);
    for (const e of res.errors) {
      console.log(`  [${e.id}] ${e.label} -> ${e.predicted} (${e.score}) ${verbose ? e.text + ' ' + e.signals.join(',') : e.text.slice(0, 70)}`);
    }
  }
}
