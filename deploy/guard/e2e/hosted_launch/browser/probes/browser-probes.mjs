import { validateConfig, lease, need, exact, result, STAGING } from './contract.mjs';

/** Runs only in the real page/worker realm through ordinary Playwright evaluate. */
async function fetchProbe(url) {
  const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 1200);
  try {
    const response = await fetch(url, { method: 'GET', mode: 'no-cors', cache: 'no-store', credentials: 'omit', redirect: 'error', signal: controller.signal });
    return { outcome: 'fetch-resolved', status: response.status, type: response.type };
  } catch { return { outcome: 'fetch-rejected' }; } finally { clearTimeout(timer); }
}
/** No SDP/candidate/address payload is returned or logged. This tests STUN UDP
 * attempted by the page; it does not claim QUIC negotiation or DNS isolation. */
async function udpProbe(host) {
  if (typeof RTCPeerConnection !== 'function') return { outcome: 'unsupported' };
  let peer;
  try {
    peer = new RTCPeerConnection({ iceServers: [{ urls: `stun:${host}:443` }], iceCandidatePoolSize: 0 });
    peer.createDataChannel('public-no-key-probe');
    await peer.setLocalDescription(await peer.createOffer());
    await new Promise(resolve => setTimeout(resolve, 1200));
    return { outcome: 'ice-attempted', gatheringState: peer.iceGatheringState };
  } catch { return { outcome: 'ice-failed' }; } finally { peer?.close(); }
}
export async function runBrowserProbes({ context, page, worker, config, authority }) {
  const c = validateConfig(config); const check = lease(c, authority); check();
  async function bounded(operation) {
    check(); let timer;
    try { const value = await Promise.race([operation, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('no_key_browser_probe_timeout')), Math.max(1, Math.min(2500, c.deadline-Date.now()))); })]); check(); return value; }
    catch { throw new Error('no_key_browser_probe_refused'); }
    finally { clearTimeout(timer); }
  }
  need(page.context() === context && context.pages().includes(page) && page.url() === STAGING
    && context.serviceWorkers().includes(worker) && worker.url() === `chrome-extension://${c.extensionId}/sw.js`);
  const welcomeUrl = `chrome-extension://${c.extensionId}/index.html#/new-user/guide`;
  const welcomes = context.pages().filter(p => p.url() === welcomeUrl); need(welcomes.length === 1);
  const welcome = welcomes[0].getByText('I already have an address', { exact: true });
  need(await welcome.count() === 1 && await welcome.isVisible()); check();
  const observations = { officialWelcomeObserved: true, extensionId: c.extensionId, targets: [], udp: null,
    interpretation: 'Fetch/CSP/proxy rejection alone is not kernel containment proof; root collector and independent namespace probes required.' };
  const urls = [
    `http://${c.network.proxyIpv4}:${c.network.deniedPort}/no-key/${c.runId}`,
    `https://${c.network.proxyIpv4}:${c.network.deniedPort}/no-key/${c.runId}`,
    `http://127.0.0.1:${c.network.deniedPort}/no-key/${c.runId}`,
    `http://[::1]:${c.network.deniedPort}/no-key/${c.runId}`,
    `http://[2001:db8::1]:${c.network.deniedPort}/no-key/${c.runId}`,
    `https://no-key-${c.runId}.invalid/no-key`,
  ];
  for (const [realm, target] of [['page', page], ['extension-worker', worker]]) {
    for (let index = 0; index < urls.length; index++) {
      check(); const observed = await bounded(target.evaluate(fetchProbe, urls[index])); check();
      need(observed && ['fetch-resolved', 'fetch-rejected'].includes(observed.outcome));
      exact(observed, observed.outcome === 'fetch-resolved' ? ['outcome','status','type'] : ['outcome']);
      if (observed.outcome === 'fetch-resolved') need(Number.isInteger(observed.status) && observed.status >= 0 && observed.status <= 599 && ['basic','cors','default','error','opaque','opaqueredirect'].includes(observed.type));
      // Keep only fixed result fields; never DOM, response bodies, headers or error text.
      observations.targets.push({ realm, target: index, outcome: observed.outcome,
        ...(observed.outcome === 'fetch-resolved' ? { status: observed.status, type: observed.type } : {}) });
    }
  }
  check(); observations.udp = await bounded(page.evaluate(udpProbe, c.network.proxyIpv4)); check();
  need(observations.udp && ['unsupported', 'ice-attempted', 'ice-failed'].includes(observations.udp.outcome));
  exact(observations.udp, observations.udp.outcome === 'ice-attempted' ? ['outcome','gatheringState'] : ['outcome']);
  if (observations.udp.outcome === 'ice-attempted') need(['new','gathering','complete'].includes(observations.udp.gatheringState));
  return result(c, 'browser-no-key', observations);
}
