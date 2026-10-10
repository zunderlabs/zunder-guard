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
  version "1.0.4"
  # Source-available, not open source: Elastic License 2.0.
  license "Elastic-2.0"

  on_macos do
    on_arm do
      url "https://github.com/zunderlabs/zunder-guard/releases/download/v1.0.4/zunder-guard-v1.0.4-darwin-arm64.tar.gz"
      sha256 "1b54077d94cb9945aa86aa83ad388b59eabb311089aeebc2f6c030986e031c9d"
    end
    on_intel do
      url "https://github.com/zunderlabs/zunder-guard/releases/download/v1.0.4/zunder-guard-v1.0.4-darwin-amd64.tar.gz"
      sha256 "15069f5e4ae18bc793f886188b48ecbb1222ede6750631a16e32ce552af6cee9"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/zunderlabs/zunder-guard/releases/download/v1.0.4/zunder-guard-v1.0.4-linux-arm64.tar.gz"
      sha256 "0b9cc3e9869ed6f9b2e488c06207898b22c644f65ba0ba83d0ace21d8f586047"
    end
    on_intel do
      url "https://github.com/zunderlabs/zunder-guard/releases/download/v1.0.4/zunder-guard-v1.0.4-linux-amd64.tar.gz"
      sha256 "28ffe6b20d61402fda00ab59b8bb86ae81d1a249117516e079f735b6fef61e6a"
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
    keep_alive successful_exit: false
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
