// Preview-only stand-in for the FastAPI demo service. Serves the same pinned
// Northwind Freight pack (copied verbatim from demo/pack/northwind_freight.v1.json)
// with the same response shapes. No auth, no audit, no database: sign-in accepts
// any 6-digit code. Only used when the build sets VITE_DEMO_MOCK=1.
import packJson from './pack.json';
import type { DemoPack } from '../api';

const clone = (): DemoPack => JSON.parse(JSON.stringify(packJson)) as DemoPack;
let live: DemoPack = clone();
let user = '';
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

const PREVIEW_QR = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200" width="200" height="200"><rect width="200" height="200" fill="#fff"/><rect x="14" y="14" width="172" height="172" fill="none" stroke="#0E141B" stroke-width="2" stroke-dasharray="6 5"/><text x="100" y="92" text-anchor="middle" font-family="Tahoma, sans-serif" font-size="13" fill="#0E141B">Preview build</text><text x="100" y="112" text-anchor="middle" font-family="Tahoma, sans-serif" font-size="11" fill="#55626e">The demo host shows the</text><text x="100" y="127" text-anchor="middle" font-family="Tahoma, sans-serif" font-size="11" fill="#55626e">real one-time TOTP QR here</text></svg>`;

export const mockApi = {
  async login(username: string, _password: string, totp_code: string) {
    await wait(350);
    if (!/^\d{6}$/.test(totp_code.trim())) throw new Error('Enter the 6-digit code from your authenticator app.');
    user = username || 'presenter-preview';
    return { token: 'preview-session', user, role: 'presenter', tenant: 'terra' };
  },
  async logout() { user = ''; return { status: 'logged_out' }; },
  async register(username: string, password: string, invite_code: string) {
    await wait(350);
    if (!invite_code.trim()) throw new Error('invalid invite code');
    if (!/^[A-Za-z0-9._-]{3,40}$/.test(username)) throw new Error('username must be 3-40 characters: letters, digits, dot, dash, underscore');
    if (password.length < 12) throw new Error('password must be at least 12 characters');
    const exp = new Date(Date.now() + 90 * 864e5).toISOString();
    return { username, qr_svg: PREVIEW_QR, expires_at: exp };
  },
  async bootstrap() {
    await wait(120);
    return {
      pack_id: live.pack_id, version: live.version,
      sha256: 'preview-build-not-pinned',
      estate: live.estate,
      user: { username: user || 'presenter-preview' },
      watermark: 'DEMO / SYNTHETIC — NOT A REAL ESTATE',
    };
  },
  async pack() { await wait(120); return live; },
  async reset() { await wait(450); live = clone(); return { status: 'reset', pack: 'northwind_freight.v1.json' }; },
  async step() { return { status: 'recorded' }; },
  async exportEvent() { return { status: 'recorded' }; },
};

export const previewApi: unknown = mockApi;
