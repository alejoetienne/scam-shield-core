import { describe, expect, it } from 'vitest';
import { analyzeRules } from '../src/index.js';

const ids = (text: string, url?: string) => analyzeRules({ text, url }).signals.map((s) => s.id);

describe('analyzeRules — result shape', () => {
  it('returns all fields in both languages', () => {
    const r = analyzeRules({ text: 'Hola, ¿cómo estás?' });
    expect(r).toMatchObject({ verdict: 'safe', category: 'none', llmUsed: false });
    expect(r.riskScore).toBeGreaterThanOrEqual(0);
    expect(r.riskScore).toBeLessThanOrEqual(100);
    for (const k of ['explanationEs', 'explanationEn', 'adviceEs', 'adviceEn'] as const) {
      expect(typeof r[k]).toBe('string');
      expect(r[k].length).toBeGreaterThan(0);
    }
  });

  it('tolerates empty or malformed input', () => {
    expect(analyzeRules({ text: '' }).verdict).toBe('safe');
    // @ts-expect-error runtime robustness
    expect(analyzeRules({}).verdict).toBe('safe');
  });

  it('signals carry bilingual reasons', () => {
    const r = analyzeRules({ text: 'Envíe el código que le llegó por SMS' });
    for (const s of r.signals) {
      expect(s.reasonEs).toBeTruthy();
      expect(s.reasonEn).toBeTruthy();
    }
  });
});

describe('domain / URL rules', () => {
  it('flags lookalike bank domains', () => {
    expect(ids('Ingrese aquí', 'https://banpro-verificacion.com')).toContain('lookalike_domain');
    expect(ids('Ingrese a https://paypa1.com/login')).toContain('lookalike_domain');
    expect(ids('Visite lafisse.net')).toContain('lookalike_domain');
  });

  it('flags punycode/homoglyph domains', () => {
    // Cyrillic "а" in pаypal
    expect(ids('Ingrese a https://pаypal.com/login')).toContain('homoglyph_domain');
    expect(ids('Ingrese a https://xn--pypal-4ve.com')).toContain('homoglyph_domain');
  });

  it('flags risky TLDs, shorteners, IP hosts, http and userinfo tricks', () => {
    expect(ids('Promo en https://ofertas.xyz')).toContain('risky_tld');
    expect(ids('Mira bit.ly/abc123')).toContain('url_shortener');
    expect(ids('Entre a http://192.168.10.5/login')).toContain('ip_host');
    expect(ids('Entre a http://tienda-ejemplo.com')).toContain('http_only');
    expect(ids('https://paypal.com@evil.example.com/x')).toContain('url_userinfo');
  });

  it('does not flag official domains', () => {
    const r = analyzeRules({ text: 'PayPal: recibiste un pago. Revisa https://www.paypal.com/activity' });
    expect(r.verdict).toBe('safe');
    expect(r.signals.map((s) => s.id)).toContain('official_domain');
    expect(analyzeRules({ text: 'Visite https://www.banpro.com.ni' }).verdict).toBe('safe');
  });

  it('flags brand mention with a non-official link', () => {
    expect(ids('BAC: actualice sus datos en https://mi-banco-seguro.com')).toContain('brand_link_mismatch');
  });
});

describe('text rules', () => {
  it('detects OTP / PIN / card / password requests', () => {
    expect(ids('Por favor díctenos el código que le enviamos')).toContain('otp_request');
    expect(ids('Envíe el número de su tarjeta y el CVV')).toContain('card_request');
    expect(ids('Confirme su usuario y contraseña')).toContain('password_request');
  });

  it('does not treat protective warnings as requests', () => {
    const r = analyzeRules({ text: 'Su código es 123456. No lo comparta con nadie. Nunca le pediremos su PIN.' });
    expect(r.signals.map((s) => s.id)).not.toContain('otp_request');
    expect(r.verdict).toBe('safe');
  });

  it('detects urgency / account blocking threats', () => {
    expect(ids('Su cuenta será bloqueada si no responde')).toContain('urgency_block');
    expect(ids('Responda inmediatamente')).toContain('urgency_time');
  });

  it('detects crypto doubling', () => {
    const r = analyzeRules({ text: 'Invierte en Bitcoin y duplica tu dinero en 48 horas' });
    expect(r.verdict).toBe('scam');
    expect(r.category).toBe('crypto_investment');
  });

  it('detects remittance retained-fee scams', () => {
    const r = analyzeRules({ text: 'Su remesa de Western Union está retenida. Pague una comisión de $30 para liberarla.' });
    expect(r.verdict).toBe('scam');
    expect(r.category).toBe('remittance_fee');
  });

  it('detects prize scams with fees', () => {
    const r = analyzeRules({ text: '¡Felicidades! Usted ha ganado un carro. Para recibir su premio pague C$2,000 de trámite.' });
    expect(r.verdict).toBe('scam');
    expect(r.category).toBe('prize_lottery');
  });

  it('detects fake jobs', () => {
    const r = analyzeRules({ text: 'Empleo desde casa, gana $80 diarios dando likes. Pagá $15 de inscripción.' });
    expect(r.verdict).toBe('scam');
    expect(r.category).toBe('fake_job');
  });

  it('detects WhatsApp number swap with money request', () => {
    const r = analyzeRules({ text: 'Hola papá, perdí mi celular, este es mi nuevo número. ¿Me podés transferir 1,000?' });
    expect(r.verdict).toBe('scam');
    expect(r.category).toBe('whatsapp_number_swap');
  });

  it('detects WhatsApp code hijack', () => {
    const r = analyzeRules({ text: 'Perdón, te mandé un código por error, me lo pasás?' });
    expect(r.signals.map((s) => s.id)).toContain('whatsapp_code_hijack');
    expect(r.verdict).not.toBe('safe');
  });
});

describe('held-out examples (not in data/samples.jsonl)', () => {
  const cases: [string, 'scam' | 'suspicious' | 'safe'][] = [
    ['BAC Credomatic: su tarjeta fue bloqueada. Desbloquéela en https://bac-desbloqueo.click', 'scam'],
    ['Banpro: hemos detectado un acceso no autorizado. Confirme su clave en http://45.33.12.9/banpro', 'scam'],
    ['Remitly: tu envío está retenido, deposita $20 de impuesto para liberar tu remesa', 'scam'],
    ['Your PayPal account will be suspended. Confirm your password at https://paypal-help.support', 'scam'],
    ['LAFISE: Pago recibido de C$800 a su tarjeta ****9921. Gracias por preferirnos.', 'safe'],
    ['Nos vemos el sábado para el almuerzo familiar.', 'safe'],
    ['Hola, guardá este número, es el nuevo mío.', 'suspicious'],
  ];
  it.each(cases)('%s → %s', (text, expected) => {
    expect(analyzeRules({ text }).verdict).toBe(expected);
  });
});
