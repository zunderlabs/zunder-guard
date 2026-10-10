import playwright from "../../site/node_modules/playwright-core/index.js";
import type {
  BrowserContext,
  Page,
  Locator,
  Worker,
} from "../../site/node_modules/playwright-core/index.js";
import { computeAddress } from "../../site/node_modules/ethers/lib.esm/index.js";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { lstat, readdir, statfs, realpath } from "node:fs/promises";
import {
  Gate,
  OWNER,
  SITE,
  refuse,
  sha,
  exact,
  hash,
  type Config,
  type Pin,
} from "./driver-policy.ts";
import { pinned } from "./driver-files.ts";
import type { PrivateInput } from "./driver-control.ts";
import type { WalletUI, Action } from "./driver-flow.ts";
export const NO_KEY_BROWSER_SHA = "982fc8705c4ad125bd247a026ee8bb8fd22dc814ac6b67a81cbcf02d352a5cec";
export const NO_KEY_CONTRACT_SHA = "41c2f715bf034fd1ab8dfca5fbbf1e82a279e748be63431c7287f9adeba634c8";
import type {NoKeyBrowserProbeInputs} from './proxy-no-key.ts';
export type {NoKeyBrowserProbeConfig,NoKeyBrowserProbeInputs} from './proxy-no-key.ts';
export interface NoKeyBrowserProbeResult {
  schema: 1; purpose: "no-key-boundary-probes"; runId: string;
  kind: "browser-no-key"; configSha256: string;
  observations: Record<string, unknown>; privateInput: false; runtimeAdmission: false;
}
/** Pure input binding only. Source hashes and config consistency grant no live
 * kernel/source admission; the real parent must independently establish it. */
export function validateNoKeyBrowserProbeInputs(input: unknown, driver: Config, extensionId: string): NoKeyBrowserProbeInputs {
  exact(input, ["modulePin", "contractPin", "config"]);
  for (const [key, name, digest] of [["modulePin", "browser-probes.mjs", NO_KEY_BROWSER_SHA], ["contractPin", "contract.mjs", NO_KEY_CONTRACT_SHA]] as const) {
    const p = input[key]; exact(p, ["path", "sha256"]);
    if (typeof p.path !== "string" || !p.path.startsWith("/opt/") || path.posix.normalize(p.path) !== p.path
      || !/^\/[A-Za-z0-9_./-]+$/.test(p.path) || path.basename(p.path) !== name || p.sha256 !== digest) refuse("source");
  }
  const v = input as unknown as NoKeyBrowserProbeInputs;
  if (path.dirname(v.modulePin.path) !== path.dirname(v.contractPin.path)) refuse("source");
  const c = v.config;
  exact(c, ["schema", "purpose", "runId", "startedAt", "deadline", "authoritySha256", "launcherSha256", "probeLauncherSha256", "profileMountPath", "extensionId", "controller", "network"]);
  if (c.schema !== 1 || c.purpose !== "no-key-boundary-probes" || c.runId !== driver.runId
    || c.startedAt !== driver.startedAt || c.deadline !== driver.deadline || c.authoritySha256 !== driver.authoritySha256
    || c.launcherSha256 !== driver.browserLauncher.sha256 || !hash(c.probeLauncherSha256)
    || c.profileMountPath !== driver.profileMountPath || c.extensionId !== extensionId || !/^[a-p]{32}$/.test(extensionId)) refuse("policy");
  exact(c.controller, ["pid", "birth", "anonymousFd", "netnsFd", "canarySha256"]);
  if (!Number.isSafeInteger(c.controller.pid) || c.controller.pid <= 1 || typeof c.controller.birth !== "string"
    || !/^[0-9]+$/.test(c.controller.birth) || !hash(c.controller.canarySha256)
    || ![c.controller.anonymousFd, c.controller.netnsFd].every(fd => Number.isInteger(fd) && fd >= 5 && fd <= 1024)
    || c.controller.anonymousFd === c.controller.netnsFd) refuse("policy");
  exact(c.network, ["proxyIpv4", "proxyPort", "deniedPort"]);
  if (c.network.proxyIpv4 !== driver.proxyEndpoint.ipv4 || c.network.proxyPort !== driver.proxyEndpoint.port
    || c.network.deniedPort !== 48731 || c.network.proxyPort === c.network.deniedPort) refuse("policy");
  return structuredClone(v);
}
/** No provider/controller/storage injection. All actions below are ordinary genuine UI controls. */
export class GenuineUI implements WalletUI {
  private context: BrowserContext | undefined;
  private onboarding: Page | undefined;
  private site: Page | undefined;
  private notification: Page | undefined;
  private worker: Worker | undefined;
  private prepared = false;
  private privateClaimed = false;
  private noKeyProbeAttempted = false;
  private noKeyProbeCompleted = false;
  private extensionId = "";
  private readonly gate: Gate;
  private readonly config: Config;
  constructor(config: Config, gate: Gate) {
    this.config = structuredClone(config);
    this.gate = gate;
  }
  private async unique(locator: Locator) {
    this.gate.check();
    await locator.waitFor({ state: "visible", timeout: this.gate.remaining() });
    this.gate.check();
    if ((await locator.count()) !== 1 || !(await locator.isVisible()))
      refuse("ui");
    this.gate.check();
    return locator;
  }
  private async click(locator: Locator) {
    await this.unique(locator);
    if (!(await locator.isEnabled())) refuse("ui");
    this.gate.check();
    await locator.click({ timeout: this.gate.remaining() });
    this.gate.check();
  }
  private async masked(locator: Locator, value?: string) {
    await this.unique(locator);
    if ((await locator.getAttribute("type")) !== "password") refuse("ui");
    if (value !== undefined) {
      this.gate.check();
      await locator.fill(value, { timeout: this.gate.remaining() });
      this.gate.check();
    } else if ((await locator.inputValue()) !== "") refuse("ui");
  }
  private async text(locator: Locator, max = 512) {
    await this.unique(locator);
    const value = await locator.textContent({ timeout: this.gate.remaining() });
    this.gate.check();
    if (value === null || Buffer.byteLength(value) > max) refuse("ui");
    return value.trim();
  }
  private ext(page: Page) {
    const url = new URL(page.url());
    if (
      url.protocol !== "chrome-extension:" ||
      url.hostname !== this.extensionId
    )
      refuse("ui");
    return url;
  }
  async prepare() {
    if (this.context || this.privateClaimed) refuse("ui");
    const home = path.join(this.config.profileMountPath, "home"),
      profile = path.join(this.config.profileMountPath, "profile"),
      tmp = path.join(this.config.profileMountPath, "tmp");
    // Root launcher owns mount/ownership preparation; driver does not create or chown it.
    const cache = path.join(this.config.profileMountPath, "cache");
    for (const directory of [home, profile, tmp, cache]) {
      if ((await realpath(directory)) !== directory) refuse("isolation");
      const info = await lstat(directory),
        fs = await statfs(directory);
      if (
        !info.isDirectory() ||
        info.uid !== 62345 ||
        info.gid !== 62345 ||
        (info.mode & 0o777) !== 0o700 ||
        Number(fs.type) !== 0x01021994
      )
        refuse("isolation");
    }
    if (
      (await readdir(profile)).length !== 0 ||
      (await readdir(tmp)).length !== 0 ||
      (await readdir(cache)).length !== 0
    )
      refuse("isolation");
    this.gate.check();
    this.context = await playwright.chromium.launchPersistentContext(profile, {
      executablePath: this.config.browserLauncher.path,
      headless: true,
      chromiumSandbox: true,
      args: [
        `--zunder-launcher-config=${this.config.launcherConfig.path}`,
        `--disable-extensions-except=${this.config.rabbyDirectory}`,
        `--load-extension=${this.config.rabbyDirectory}`,
      ],
      proxy: {
        server: `http://${this.config.proxyEndpoint.ipv4}:${this.config.proxyEndpoint.port}`,
      },
      env: {
        HOME: home,
        TMPDIR: tmp,
        XDG_CACHE_HOME: cache,
        LANG: "en_US.UTF-8",
      },
      locale: "en-US",
      acceptDownloads: false,
      timeout: this.gate.remaining(),
      handleSIGINT: false,
      handleSIGTERM: false,
      handleSIGHUP: false,
    });
    if (this.gate.reason()) {
      await this.context.close().catch(() => {});
      refuse("closed");
    }
    this.context.setDefaultTimeout(Math.min(5000, this.gate.remaining()));
    this.context.on("page", (page) => {
      page.on("dialog", () => this.gate.hold("ui"));
      page.on("download", () => this.gate.hold("ui"));
    });
    const workers = this.context.serviceWorkers();
    if (workers.length > 1) refuse("source");
    const worker =
      workers.length === 1
        ? workers[0]!
        : await this.context.waitForEvent("serviceworker", {
            timeout: this.gate.remaining(),
          });
    const url = new URL(worker.url());
    if (
      url.protocol !== "chrome-extension:" ||
      !/^[a-p]{32}$/.test(url.hostname)
    )
      refuse("source");
    this.extensionId = url.hostname;
    this.worker = worker;
    const existing = this.context
      .pages()
      .filter((p) =>
        p.url().startsWith(`chrome-extension://${this.extensionId}/index.html`),
      );
    if (existing.length > 1) refuse("ui");
    this.onboarding = existing[0] ?? (await this.context.newPage());
    await this.onboarding.goto(
      `chrome-extension://${this.extensionId}/index.html#/new-user/guide`,
      { waitUntil: "domcontentloaded", timeout: this.gate.remaining() },
    );
    const p = this.onboarding;
    await this.click(p.getByText("I already have an address", { exact: true }));
    await this.click(
      p.getByText("Seed Phrase or Private Key", { exact: true }),
    );
    await this.click(p.getByText("Private Key", { exact: true }));
    if (this.ext(p).hash !== "#/new-user/import/seed-or-key") refuse("ui");
    await this.masked(p.getByPlaceholder("Input private key", { exact: true }));
    this.prepared = true;
    return {
      extensionId: this.extensionId,
      observationSha256: sha(
        JSON.stringify({
          extensionId: this.extensionId,
          route: this.ext(p).hash,
          masked: true,
          empty: true,
          version: "0.94.11",
        }),
      ),
    };
  }
  /** Read-only browser observation in this exact keyless instance. The internal
   * Gate/digests limit observation scope; they do NOT replace the parent's live
   * watchdog, source, namespace or independent kernel admission checks. */
  async runNoKeyBrowserProbes(input: NoKeyBrowserProbeInputs): Promise<NoKeyBrowserProbeResult> {
    if (this.noKeyProbeAttempted || this.privateClaimed || !this.prepared || !this.context || !this.onboarding || !this.worker) refuse("ui");
    this.noKeyProbeAttempted = true;
    const context = this.context, onboarding = this.onboarding, worker = this.worker;
    let page: Page | undefined;
    return this.gate.step(async () => {
      const c = validateNoKeyBrowserProbeInputs(input, this.config, this.extensionId);
      // The controller is the original parent's forbidden-process fixture,
      // independently authenticated by root; it need not be this Node process.
      if (this.gate.startedAt !== c.config.startedAt || this.gate.deadline !== c.config.deadline) refuse("policy");
      if (this.ext(onboarding).hash !== "#/new-user/import/seed-or-key") refuse("ui");
      await this.masked(onboarding.getByPlaceholder("Input private key", { exact: true }));
      try {
        // Both reviewed files are checked before import; no caller-supplied function
        // or arbitrary sibling dependency can run in the controller.
        await pinned(c.contractPin, 32768); this.gate.check();
        await pinned(c.modulePin, 32768); this.gate.check();
        const module = await import(pathToFileURL(c.modulePin.path).href);
        if (Object.keys(module).join(",") !== "runBrowserProbes" || typeof module.runBrowserProbes !== "function") refuse("source");
        this.gate.check();
        await onboarding.goto(`chrome-extension://${this.extensionId}/index.html#/new-user/guide`, { waitUntil: "domcontentloaded", timeout: this.gate.remaining() });
        await this.unique(onboarding.getByText("I already have an address", { exact: true }));
        page = await context.newPage();
        await page.goto(SITE + "/approve", { waitUntil: "domcontentloaded", timeout: this.gate.remaining() });
        this.gate.check();
        const configSha256 = sha(JSON.stringify(c.config));
        const authority = Object.freeze({ assertNoKeyLive: (digest: string, authoritySha256: string) => {
          if (digest !== configSha256 || authoritySha256 !== this.config.authoritySha256 || this.privateClaimed) refuse("policy");
          this.gate.check();
        } });
        const result: unknown = await module.runBrowserProbes({ context, page, worker, config: c.config, authority });
        this.gate.check();
        exact(result, ["schema", "purpose", "runId", "kind", "configSha256", "observations", "privateInput", "runtimeAdmission"]);
        if (result.schema !== 1 || result.purpose !== "no-key-boundary-probes" || result.runId !== this.config.runId
          || result.kind !== "browser-no-key" || result.configSha256 !== configSha256 || result.privateInput !== false || result.runtimeAdmission !== false
          || !result.observations || typeof result.observations !== "object" || Array.isArray(result.observations)) refuse("ui");
        await page.close(); page = undefined; this.gate.check();
        // Restore the same empty masked import page using genuine controls only.
        await this.click(onboarding.getByText("I already have an address", { exact: true }));
        await this.click(onboarding.getByText("Seed Phrase or Private Key", { exact: true }));
        await this.click(onboarding.getByText("Private Key", { exact: true }));
        if (this.ext(onboarding).hash !== "#/new-user/import/seed-or-key") refuse("ui");
        await this.masked(onboarding.getByPlaceholder("Input private key", { exact: true }));
        this.noKeyProbeCompleted = true;
        return structuredClone(result) as unknown as NoKeyBrowserProbeResult;
      } finally {
        if (page) await page.close().catch(() => this.gate.hold("closed"));
      }
    });
  }
  async import(input: PrivateInput) {
    if (this.privateClaimed) refuse("private-input");
    this.privateClaimed = true;
    if (this.noKeyProbeAttempted && !this.noKeyProbeCompleted) {
      this.gate.hold("private-input");
      refuse("private-input");
    }
    this.gate.check();
    if (!this.onboarding || !this.context) refuse("ui");
    let address: string;
    try {
      address = computeAddress(input.ownerPrivateKey).toLowerCase();
    } catch {
      refuse("private-input");
    }
    if (address !== OWNER) refuse("private-input");
    const p = this.onboarding;
    await this.masked(
      p.getByPlaceholder("Input private key", { exact: true }),
      input.ownerPrivateKey,
    );
    await this.click(p.getByRole("button", { name: "Next", exact: true }));
    if (this.ext(p).hash !== "#/new-user/import/private-key/set-password")
      refuse("ui");
    await this.masked(
      p.getByPlaceholder("Password (8 characters min)", { exact: true }),
      input.vaultPassword,
    );
    await this.masked(
      p.getByPlaceholder("Confirm Password", { exact: true }),
      input.vaultPassword,
    );
    await this.click(p.getByRole("button", { name: "Confirm", exact: true }));
    await this.unique(p.getByText("Address Imported", { exact: true }));
    await this.click(
      p.getByRole("button", { name: "Open Wallet", exact: true }),
    );
  }
  async configureNetwork() {
    if (!this.onboarding) refuse("ui");
    const p = this.onboarding;
    this.ext(p);
    // Source-backed ordinary settings route; no controller/storage or manufactured approval route.
    await p.goto(
      `chrome-extension://${this.extensionId}/index.html#/custom-testnet`,
      { waitUntil: "domcontentloaded", timeout: this.gate.remaining() },
    );
    await this.click(
      p.getByRole("button", { name: "Add Custom Network", exact: true }),
    );
    const fields = [
      ["Chain ID", "421614"],
      ["Network name", "Arbitrum Sepolia"],
      ["RPC URL", "https://sepolia-rollup.arbitrum.io/rpc"],
      ["Currency symbol", "ETH"],
    ] as const;
    for (const [label, value] of fields) {
      const input = p.getByLabel(label, { exact: true });
      await this.unique(input);
      if ((await input.inputValue()) !== "") refuse("ui");
      this.gate.check();
      await input.fill(value, { timeout: this.gate.remaining() });
      this.gate.check();
    }
    const optional = p.getByLabel("Block explorer URL (Optional)", {
      exact: true,
    });
    await this.unique(optional);
    if ((await optional.inputValue()) !== "") refuse("ui");
    for (const [label, value] of fields)
      if ((await p.getByLabel(label, { exact: true }).inputValue()) !== value)
        refuse("ui");
    await this.click(p.getByRole("button", { name: "Confirm", exact: true }));
    // Rabby's own real RPC validation must succeed and close the modal.
    await p
      .getByLabel("Chain ID", { exact: true })
      .waitFor({ state: "hidden", timeout: this.gate.remaining() });
    await this.unique(p.getByText("Arbitrum Sepolia", { exact: true }));
  }
  private async siteIdentity() {
    if (!this.site || this.site.url() !== SITE + "/approve") refuse("ui");
    const article = this.site.locator("[data-approve]");
    await this.unique(article);
    if (
      (await article.getAttribute("data-deployment-profile")) !== "staging" ||
      (await article.getAttribute("data-mainnet")) !== "0" ||
      (await article.getAttribute("data-builder-testnet")) !==
        this.config.builder
    )
      refuse("source");
  }
  private async connectedIdentity() {
    await this.siteIdentity();
    if (!this.site) refuse("ui");
    if (
      (
        await this.site.locator("[data-conn-addr]").getAttribute("title")
      )?.toLowerCase() !== OWNER
    )
      refuse("ui");
    const net = await this.text(this.site.locator("[data-conn-net]"));
    if (net !== "Hyperliquid Testnet · wallet on Arbitrum Sepolia")
      refuse("ui");
  }
  private async nextNotification(trigger: () => Promise<void>) {
    if (!this.context) refuse("ui");
    const context = this.context;
    if (
      context
        .pages()
        .some((p) =>
          p
            .url()
            .startsWith(
              `chrome-extension://${this.extensionId}/notification.html`,
            ),
        )
    )
      refuse("ui");
    const notification = context.waitForEvent("page", {
      timeout: this.gate.remaining(),
    });
    void notification.catch(() => {});
    await trigger();
    const p = await notification;
    await p.waitForLoadState("domcontentloaded", {
      timeout: this.gate.remaining(),
    });
    const url = this.ext(p);
    if (url.pathname !== "/notification.html") refuse("ui");
    this.notification = p;
  }
  async connect() {
    if (!this.context) refuse("ui");
    this.site = await this.context.newPage();
    await this.site.goto(SITE + "/approve", {
      waitUntil: "domcontentloaded",
      timeout: this.gate.remaining(),
    });
    await this.siteIdentity();
    const testnet = this.site.locator('[data-net="testnet"]');
    if ((await testnet.getAttribute("aria-checked")) !== "true")
      await this.click(testnet);
    await this.nextNotification(() =>
      this.click(
        this.site!.locator("[data-wallets]").getByRole("button", {
          name: /Rabby/,
        }),
      ),
    );
    const p = this.notification!;
    await this.unique(p.getByText("Connect to Dapp", { exact: true }));
    if ((await this.text(p.locator(".connect-origin"))) !== SITE) refuse("ui");
    await this.click(p.locator(".approval-connect .chain-selector"));
    await this.click(p.getByText("Custom Network", { exact: true }));
    const row = p.locator(".select-chain-item").filter({
      has: p
        .locator(".select-chain-item-name")
        .filter({ hasText: /^Arbitrum Sepolia$/ }),
    });
    await this.unique(row);
    if (
      (await row.getAttribute("class"))
        ?.split(/\s+/)
        .includes("select-chain-item-disabled")
    )
      refuse("ui");
    await this.click(row);
    if (
      (await this.text(p.locator(".approval-connect .chain-selector"))) !==
      "Arbitrum Sepolia"
    )
      refuse("ui");
    await this.click(p.getByRole("button", { name: "Connect", exact: true }));
    await this.connectedIdentity();
  }
  async prompt(action: "reject" | Action) {
    await this.connectedIdentity();
    await this.nextNotification(() =>
      this.click(
        this.site!.locator(
          action === "restore" ? "[data-withdraw]" : "[data-sign]",
        ),
      ),
    );
  }
  private async promptIdentity() {
    if (!this.notification || this.notification.isClosed()) refuse("ui");
    this.ext(this.notification);
    await this.connectedIdentity();
    for (const label of ["Failed", "Refresh", "Ignore all"])
      if (await this.notification.getByText(label, { exact: true }).isVisible())
        refuse("ui");
    const footer = this.notification.locator("footer.approval-text__footer");
    await this.unique(footer);
    const signer = footer.locator(".address-viewer-text");
    await this.unique(signer);
    if ((await signer.getAttribute("title")) !== OWNER) refuse("ui");
    if ((await this.text(this.notification.locator(".origin"))) !== SITE)
      refuse("ui");
  }
  async inspect() {
    await this.promptIdentity();
    const raw = this.notification!.locator(
      "div.whitespace-pre-wrap.overflow-y-auto",
    ).filter({ hasText: "HyperliquidTransaction:ApproveBuilderFee" });
    return this.text(raw, 8192);
  }
  async cancel() {
    await this.promptIdentity();
    await this.click(
      this.notification!.getByRole("button", { name: "Cancel", exact: true }),
    );
  }
  async sign() {
    await this.promptIdentity();
    await this.click(
      this.notification!.getByRole("button", { name: "Sign", exact: true }),
    );
  }
  async confirm() {
    await this.promptIdentity();
    await this.click(
      this.notification!.getByRole("button", { name: "Confirm", exact: true }),
    );
  }
  async rejected() {
    await this.connectedIdentity();
    await this.cap(0);
    if (!this.site) refuse("ui");
    await this.unique(this.site.locator("[data-log]").getByText(/rejected/i));
  }
  async cap(value: 0 | 20) {
    await this.connectedIdentity();
    const expected = value === 0 ? "Not approved" : "Approved: 0.02%";
    if ((await this.text(this.site!.locator("[data-state-text]"))) !== expected)
      refuse("ui");
  }
  async close() {
    this.prepared = false;
    if (this.context) await this.context.close();
  }
}
