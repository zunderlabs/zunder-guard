// The licence checkout's shared facts for the page (pages/licence.astro, scripts/licence.ts). The
// Worker (web/waitlist/src/licence/core.ts) decides prices, VAT and countries again on the server;
// scripts/checkout-check.mjs compares the two lists.
import { LICENCES } from './pricing';

export const EU = ['AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE'];
export const BLOCKED = ['RU', 'BY', 'IR', 'KP', 'CU', 'SY'];
export const COUNTRIES = (
  'AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ ' +
  'CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR ' +
  'GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP ' +
  'KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT ' +
  'MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW ' +
  'SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG ' +
  'UM US UY UZ VA VC VE VG VI VN VU WF WS XK YE YT ZA ZM ZW'
).split(' ');

/** Countries a licence can be sold to, named in English (Intl, so no list of names to keep). */
export function countryOptions(): { code: string; name: string }[] {
  const names = new Intl.DisplayNames(['en'], { type: 'region' });
  return COUNTRIES.filter((c) => !BLOCKED.includes(c))
    .map((code) => ({ code, name: code === 'XK' ? 'Kosovo' : names.of(code) ?? code }))
    .sort((a, b) => a.name.localeCompare(b.name, 'en'));
}

export type PayNetwork = 'hyperliquid' | 'arbitrum' | 'base';
export const NETWORKS: { id: PayNetwork; label: string; hint: string }[] = [
  { id: 'hyperliquid', label: 'Hyperliquid', hint: 'USDC on Hyperliquid · transfer fees may apply' },
  { id: 'arbitrum', label: 'Arbitrum', hint: 'USDC, confirmed once final (minutes)' },
  { id: 'base', label: 'Base', hint: 'USDC, confirmed once final (minutes)' },
];

/** The Terms version a buyer accepts (legal/terms-of-use.md, "Version"). */
export const TERMS_VERSION = '2026-10-06';

export { LICENCES };
