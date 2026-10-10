# Homebrew formula for Zunder Guard. Rendered by deploy/guard/packaging/render.sh for each
# release (version and checksums filled in) and committed to github.com/zunderlabs/homebrew-tap
# as Formula/zunder-guard.rb:
#
#   brew install zunderlabs/tap/zunder-guard
#
# Homebrew checks the SHA-256 below, which the release workflow took from the signed release.
# To check the Sigstore signature as well, follow "Verify this release" in the README.
class ZunderGuard < Formula
  desc "Self-hosted risk firewall between trading bots or AI agents and Hyperliquid"
  homepage "https://zunderlabs.com"
  version "1.0.5"
  # Source-available, not open source: Elastic License 2.0.
  license "Elastic-2.0"

  on_macos do
    on_arm do
      url "https://github.com/zunderlabs/zunder-guard/releases/download/v1.0.5/zunder-guard-v1.0.5-darwin-arm64.tar.gz"
      sha256 "224b1a95f07bdc0899b365ce2d2eeaf0f275db2e80465cdcb307bd4fd757e7d4"
    end
    on_intel do
      url "https://github.com/zunderlabs/zunder-guard/releases/download/v1.0.5/zunder-guard-v1.0.5-darwin-amd64.tar.gz"
      sha256 "2e8d9947fa392a0fea55e28615172f367592e1ed20835996bc577a61efce901b"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/zunderlabs/zunder-guard/releases/download/v1.0.5/zunder-guard-v1.0.5-linux-arm64.tar.gz"
      sha256 "39f8581579a3dd58f1f8c6812e5ca3d49510a10026794bfb4394a37353b1c0da"
    end
    on_intel do
      url "https://github.com/zunderlabs/zunder-guard/releases/download/v1.0.5/zunder-guard-v1.0.5-linux-amd64.tar.gz"
      sha256 "055073b2c813deafec8120f899e87e70c6a6d016e3c26d0a33a0da568136b295"
    end
  end

  def install
    bin.install "zunder-guard"
    pkgshare.install "LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md"
  end

  # Paper mode on 127.0.0.1 (unless `init` chose another address). `run` sends only where
  # --network says and only when that is the mode init recorded, so a testnet or mainnet setup
  # refuses this service. Sending modes use an explicit foreground start (caveats).
  service do
    run [opt_bin/"zunder-guard", "run", "--network", "paper"]
    environment_variables ZUNDER_GUARD_HOME: var/"zunder-guard"
    # launchd uses SuccessfulExit=false; systemd needs crashed=true for on-failure.
    keep_alive successful_exit: false, crashed: true
    log_path var/"log/zunder-guard.log"
    error_log_path var/"log/zunder-guard.log"
  end

  def caveats
    <<~EOS
      Use the same home for setup, pairing, licence commands and every start:
        export ZUNDER_GUARD_HOME="#{var}/zunder-guard"
        zunder-guard init --interactive
      Init creates your first client key and pairing code. To add another bot:
        zunder-guard pair
      Restart Guard after adding a client. Keep pairing output private.

      Paper mode only:
        brew services start zunder-guard
      For a testnet config, stop the service and run explicitly:
        brew services stop zunder-guard
        zunder-guard run --network testnet

      Mainnet works in the foreground on macOS and Linux. Guided init asks you to
      type mainnet, confirm the account and choose the equity cap; it checks the
      API wallet key without storing it. At your go-ahead, initialize the mainnet
      journal with journal-init --mode mainnet --note, then start with
      run --network mainnet --key-stdin. Both commands require
      ZUNDER_MAINNET_CONFIRM naming the configured account; run needs the key
      from your secret manager on standard input at every start.
      brew services cannot provide that credential and remains paper-only.
      For unattended mainnet use the separately verified protected installer:
      Linux uses systemd-creds; macOS uses System Keychain and launchd.
      Never elevate a user-writable Homebrew Cellar executable for that setup.

      Setup, licence activation, restart, upgrades and removal:
        https://zunderlabs.com/docs/deploy/packages/
      Guard's default listen address is 127.0.0.1:8547.
    EOS
  end

  test do
    assert_match "zunder-guard", shell_output("#{bin}/zunder-guard --version")
    %w[LICENSE NOTICE THIRD_PARTY_LICENSES.md].each do |notice|
      assert_path_exists pkgshare/notice
    end
  end
end
