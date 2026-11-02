import { describe, expect, it } from 'vitest';
import { decodePunycodeLabel, detectLookalike, extractUrls, hostnameToUnicode, parseUrl, skeleton } from '../src/index.js';

describe('punycode', () => {
  it('decodes known labels', () => {
    expect(decodePunycodeLabel('mnchen-3ya')).toBe('münchen');
    expect(hostnameToUnicode('xn--mnchen-3ya.de')).toBe('münchen.de');
    expect(hostnameToUnicode('example.com')).toBe('example.com');
  });
  it('leaves invalid labels untouched', () => {
    expect(hostnameToUnicode('xn--!!!.com')).toBe('xn--!!!.com');
  });
});

describe('extractUrls / parseUrl', () => {
  it('finds URLs with and without scheme, skipping emails and numbers', () => {
    const urls = extractUrls('Visite https://a.com/x, bit.ly/abc y www.b.org. Correo: yo@c.com. Monto C$1,500.00');
    expect(urls).toEqual(['https://a.com/x', 'bit.ly/abc', 'www.b.org']);
  });
  it('parses hosts, registrable domains and flags', () => {
    const p = parseUrl('http://user@login.banpro.com.ni:8080/path')!;
    expect(p.host).toBe('login.banpro.com.ni');
    expect(p.registrable).toBe('banpro.com.ni');
    expect(p.scheme).toBe('http');
    expect(p.hasUserInfo).toBe(true);
    expect(parseUrl('10.0.0.1/x')!.isIp).toBe(true);
  });
});

describe('lookalikes', () => {
  it('maps confusables to a skeleton', () => {
    expect(skeleton('paypa1')).toBe('paypal');
    expect(skeleton('bаnpro')).toBe('banpro');
  });
  it('detects imitation but not official domains', () => {
    expect(detectLookalike(parseUrl('banpr0.com')!)?.id).toBe('banpro');
    expect(detectLookalike(parseUrl('bac-nicaragua.xyz')!)?.id).toBe('bac');
    expect(detectLookalike(parseUrl('www.banpro.com.ni')!)).toBeUndefined();
    expect(detectLookalike(parseUrl('www.baccredomatic.com')!)).toBeUndefined();
    expect(detectLookalike(parseUrl('bacon-recipes.com')!)).toBeUndefined();
  });
});
