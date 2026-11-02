import { describe, expect, it, vi } from 'vitest';
import { analyze, analyzeRules, parseAssessment, resolveProvider } from '../src/index.js';
import type { FetchLike } from '../src/index.js';

const SCAM = 'BAC: su cuenta será bloqueada. Envíe el código que le llegó por SMS.';
const SAFE = 'Hola, ¿nos vemos mañana a las 3?';

function mockFetch(body: unknown, ok = true, status = 200) {
  return vi.fn<FetchLike>(async () => ({ ok, status, json: async () => body, text: async () => JSON.stringify(body) }));
}

describe('provider resolution', () => {
  it('is disabled by default and without keys', () => {
    expect(resolveProvider({ env: {} })).toBeNull();
    expect(resolveProvider({ env: { SCAM_SHIELD_LLM: 'none', ANTHROPIC_API_KEY: 'k' } })).toBeNull();
    expect(resolveProvider({ env: { SCAM_SHIELD_LLM: 'anthropic' } })).toBeNull();
    expect(resolveProvider({ env: { SCAM_SHIELD_LLM: 'bogus', OPENAI_API_KEY: 'k' } })).toBeNull();
  });
  it('reads provider, key and model from env', () => {
    expect(resolveProvider({ env: { SCAM_SHIELD_LLM: 'openai', OPENAI_API_KEY: 'k' } })).toMatchObject({ name: 'openai', apiKey: 'k' });
    expect(resolveProvider({ env: { SCAM_SHIELD_LLM: 'Gemini', GEMINI_API_KEY: 'g', SCAM_SHIELD_GEMINI_MODEL: 'm' } })).toEqual({ name: 'gemini', apiKey: 'g', model: 'm' });
  });
});

describe('parseAssessment', () => {
  it('extracts JSON wrapped in prose and clamps values', () => {
    const a = parseAssessment('Here: {"riskScore": 140, "verdict": "scam", "category": "fake_job", "reasonEs": "x", "reasonEn": "y"} done');
    expect(a).toEqual({ riskScore: 100, verdict: 'scam', category: 'fake_job', reasonEs: 'x', reasonEn: 'y' });
  });
  it('rejects garbage', () => {
    expect(parseAssessment('no json')).toBeNull();
    expect(parseAssessment('{"riskScore":"abc"}')).toBeNull();
  });
});

describe('analyze()', () => {
  it('equals rules-only when no LLM is configured', async () => {
    const fetch = mockFetch({});
    const r = await analyze({ text: SCAM }, { env: {}, fetch });
    expect(r).toEqual(analyzeRules({ text: SCAM }));
    expect(r.llmUsed).toBe(false);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('blends an Anthropic assessment', async () => {
    const fetch = mockFetch({ content: [{ type: 'text', text: '{"riskScore":80,"verdict":"scam","category":"bank_impersonation","reasonEs":"Pide código","reasonEn":"Asks for code"}' }] });
    const r = await analyze({ text: SAFE }, { env: { SCAM_SHIELD_LLM: 'anthropic', ANTHROPIC_API_KEY: 'k' }, fetch });
    expect(r.llmUsed).toBe(true);
    expect(r.riskScore).toBe(Math.round(0.6 * analyzeRules({ text: SAFE }).riskScore + 0.4 * 80));
    expect(r.signals.some((s) => s.id === 'llm_anthropic')).toBe(true);
    const [url, init] = fetch.mock.calls[0]!;
    expect(url).toBe('https://api.anthropic.com/v1/messages');
    expect(init?.headers?.['x-api-key']).toBe('k');
  });

  it('works with OpenAI and Gemini response shapes', async () => {
    const json = '{"riskScore":10,"verdict":"safe","category":"none","reasonEs":"ok","reasonEn":"ok"}';
    const o = await analyze({ text: SAFE }, { llm: 'openai', apiKey: 'k', env: {}, fetch: mockFetch({ choices: [{ message: { content: json } }] }) });
    expect(o.llmUsed).toBe(true);
    const g = await analyze({ text: SAFE }, { llm: 'gemini', apiKey: 'k', env: {}, fetch: mockFetch({ candidates: [{ content: { parts: [{ text: json }] } }] }) });
    expect(g.llmUsed).toBe(true);
  });

  it('cannot be talked below "scam" when strong rule evidence exists', async () => {
    const fetch = mockFetch({ content: [{ type: 'text', text: '{"riskScore":0,"verdict":"safe","category":"none","reasonEs":"","reasonEn":""}' }] });
    const r = await analyze({ text: SCAM }, { llm: 'anthropic', apiKey: 'k', env: {}, fetch });
    expect(r.verdict).toBe('scam');
  });

  it('falls back to rules on HTTP error, invalid JSON, or thrown fetch', async () => {
    const env = { SCAM_SHIELD_LLM: 'openai', OPENAI_API_KEY: 'k' };
    const rules = analyzeRules({ text: SCAM });
    for (const fetch of [
      mockFetch({ error: 'x' }, false, 500),
      mockFetch({ choices: [{ message: { content: 'not json' } }] }),
      vi.fn<FetchLike>(async () => { throw new Error('network'); }),
    ]) {
      const r = await analyze({ text: SCAM }, { env, fetch });
      expect(r).toEqual(rules);
    }
  });

  it('times out slow providers and falls back', async () => {
    const fetch = vi.fn<FetchLike>((_u, init) => new Promise((_, rej) => init?.signal?.addEventListener('abort', () => rej(new Error('aborted')))));
    const r = await analyze({ text: SCAM }, { llm: 'gemini', apiKey: 'k', env: {}, fetch, timeoutMs: 20 });
    expect(r.llmUsed).toBe(false);
  });
});
