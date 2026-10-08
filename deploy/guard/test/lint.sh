#!/usr/bin/env bash
# Static checks of everything in deploy/guard, on the Linux build host (deploy/guard/README.md,
# "Testing"): shellcheck (scripts and the generated SSH one-liner), actionlint, hadolint,
# systemd-analyze verify, cloud-init's schema, cfn-lint, the Railway, Render and winget JSON
# schemas, PSScriptAnalyzer on the Windows installer, fly.toml, and Ruby's syntax check of the rendered Homebrew formula. Tools come from
# Ubuntu, pinned container images or a private Python venv (cfn-lint MIT-0, check-jsonschema
# Apache-2.0); they check our files and are not shipped.
set -euo pipefail
cd "$(dirname "$0")/../../.."
G=deploy/guard
DOCKER=docker
id -nG | grep -qw docker || DOCKER="sudo docker"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
VENV=$HOME/.cache/guard-lint-venv
if [ ! -x "$VENV/bin/cfn-lint" ]; then
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q cfn-lint check-jsonschema
fi
step() { echo "== $*"; }

step "shellcheck"
shellcheck --version | sed -n 2p
shellcheck -s sh $G/install.sh $G/loader/i.sh $G/test/fake-cosign
shellcheck $G/packaging/*.sh $G/github/*.sh $G/test/*.sh $G/macos/*.sh
# The one-liner exactly as the website generates it, and the command it runs on the server.
cat >"$W/oneliner.sh" <<'EOF'
#!/bin/sh
ssh -t you@server "curl -fsSL https://zunderlabs.com/i | sh -s -- --rules zr1_eyJ2IjoxfQ"
EOF
cat >"$W/remote.sh" <<'EOF'
#!/bin/sh
curl -fsSL https://zunderlabs.com/i | sh -s -- --rules zr1_eyJ2IjoxfQ
EOF
cat >"$W/inspect-first.sh" <<'EOF'
#!/bin/sh
curl -fsSLO https://zunderlabs.com/i && less i && sh i --rules zr1_eyJ2IjoxfQ
EOF
shellcheck -s sh "$W/oneliner.sh" "$W/remote.sh" "$W/inspect-first.sh"
# Optional cloud-init source is checked when present.
if [ -f "$G/templates/cloud-init.yaml" ]; then
# The cloud-init and CloudFormation commands, extracted.
python3 - "$G/templates/cloud-init.yaml" >"$W/cloud-init-cmd.sh" <<'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
print("#!/bin/sh")
for c in doc["runcmd"]:
    print(c[2] if c[:2] == ["sh", "-c"] else " ".join(c))
PY
shellcheck -s sh "$W/cloud-init-cmd.sh"
echo "  ok: scripts, the one-liner, the inspect-first form, the cloud-init commands"
fi

step "actionlint"
$DOCKER run --rm -v "$PWD/$G/github/workflows:/w:ro" -w /w rhysd/actionlint:1.7.12 -no-color release.yml publish.yml ci.yml
echo "  ok: release.yml publish.yml ci.yml"

step "hadolint"
$DOCKER run --rm -i hadolint/hadolint:v2.15.1 hadolint --no-color - <$G/Dockerfile
echo "  ok: Dockerfile"

step "systemd-analyze verify"
mkdir -p "$W/unit"
cp $G/systemd/zunder-guard.service "$W/unit/"
sed -i 's|/usr/local/bin/zunder-guard|/bin/true|' "$W/unit/zunder-guard.service"
systemd-analyze verify "$W/unit/zunder-guard.service" && echo "  ok: unit"

step "cloud-init schema"
if [ -f "$G/templates/cloud-init.yaml" ]; then cloud-init schema -c $G/templates/cloud-init.yaml; fi

step "cfn-lint"
"$VENV/bin/cfn-lint" --version
"$VENV/bin/cfn-lint" --regions ap-northeast-1 eu-central-1 us-east-1 -- $G/templates/cloudformation.yaml \
  && echo "  ok: cloudformation.yaml"

step "JSON schemas: Railway, Render, winget"
fetch() { curl -fsSL --retry 3 -o "$W/$1" "$2"; }
if [ -f "$G/templates/railway.json" ]; then
fetch railway.schema.json https://railway.com/railway.schema.json
"$VENV/bin/check-jsonschema" --schemafile "$W/railway.schema.json" $G/templates/railway.json
fi
if [ -f "$G/templates/render.yaml" ]; then
if fetch render.schema.json https://render.com/schema/render.yaml.json; then
  "$VENV/bin/check-jsonschema" --schemafile "$W/render.schema.json" $G/templates/render.yaml
else
  echo "  note: Render's schema could not be fetched; render.yaml checked as YAML only"
  python3 -c 'import sys, yaml; yaml.safe_load(open(sys.argv[1]))' $G/templates/render.yaml
fi
fi
sub() {
  sed -e 's/@VERSION@/v1.2.3/g; s/@VERSION_NUMBER@/1.2.3/g; s/@RELEASE_DATE@/2026-10-06/g' \
    -e 's/@SHA256_[A-Z0-9_]*_UPPER@/'"$(printf 'A%.0s' $(seq 64))"'/g' \
    -e 's/@SHA256_[A-Z0-9_]*@/'"$(printf 'a%.0s' $(seq 64))"'/g' "$1"
}

WG=https://raw.githubusercontent.com/microsoft/winget-cli/master/schemas/JSON/manifests/v1.10.0
for pair in "ZunderLabs.ZunderGuard:manifest.version.1.10.0" \
  "ZunderLabs.ZunderGuard.installer:manifest.installer.1.10.0" \
  "ZunderLabs.ZunderGuard.locale.en-US:manifest.defaultLocale.1.10.0"; do
  file=${pair%%:*} schema=${pair#*:}
  fetch "$schema.json" "$WG/$schema.json"
  sub "$G/packaging/winget/$file.yaml.in" >"$W/$file.yaml"
  "$VENV/bin/check-jsonschema" --schemafile "$W/$schema.json" "$W/$file.yaml"
done

step "PowerShell: i.ps1 and its Windows test parse; PSScriptAnalyzer"
sub $G/loader/i.ps1 >"$W/i.ps1"
cp $G/test/installer-windows.ps1 "$W/"
# The .NET SDK image is multi-arch and ships pwsh (PowerShell's own image is amd64 only).
# shellcheck disable=SC2016 # PowerShell, not shell, expands these
$DOCKER run --rm -v "$W:/w:ro" mcr.microsoft.com/dotnet/sdk:9.0-noble pwsh -NoProfile -Command '
  $ErrorActionPreference = "Stop"
  foreach ($f in "/w/i.ps1", "/w/installer-windows.ps1") {
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$null, [ref]$errors) | Out-Null
    if ($errors) { $errors | ForEach-Object { Write-Host $_ }; throw "parse errors in $f" }
  }
  if ([Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes("/w/i.ps1")) -match "[^\x00-\x7F]") { throw "i.ps1 must be ASCII (Windows PowerShell 5.1 reads it as ANSI)" }
  Set-PSRepository PSGallery -InstallationPolicy Trusted
  Install-Module PSScriptAnalyzer -RequiredVersion 1.24.0 -Scope CurrentUser -Force | Out-Null
  $found = Invoke-ScriptAnalyzer -Path /w/i.ps1 -Severity Warning,Error -ExcludeRule PSAvoidUsingWriteHost
  if ($found) { $found | Format-Table -AutoSize | Out-String | Write-Host; throw "PSScriptAnalyzer findings" }
  # Not on Windows it refuses clearly, and never exits the calling shell.
  try { & ([scriptblock]::Create((Get-Content -Raw /w/i.ps1))) -InstallOnly; throw "went through" }
  catch { if ($_.Exception.Message -notlike "*for Windows*") { throw $_ } }
  Write-Host "  ok: both parse, ASCII, no analyzer findings, refuses on Linux"
'

if [ -f "$G/templates/fly.toml" ]; then
step "fly.toml"
python3 - $G/templates/fly.toml <<'PY'
import sys, tomllib
c = tomllib.load(open(sys.argv[1], "rb"))
assert c["primary_region"] == "nrt", "Tokyo"
assert "http_service" not in c and "services" not in c, "no public service by default"
assert c["mounts"]["destination"] == "/data"
assert not any("KEY" in k and "FILE" not in k for k in c["env"]), "no key in env"
print("  ok: parses; nrt; no public service; volume at /data; no key in [env]")
PY

fi

step "Homebrew formula (Ruby syntax)"
sub $G/packaging/homebrew/zunder-guard.rb.in >"$W/zunder-guard.rb"
ruby -c "$W/zunder-guard.rb"

step "compose"
ZUNDER_GUARD_IMAGE=x $DOCKER compose -f $G/compose.yaml config -q && echo "  ok: compose.yaml"
grep -q '"127.0.0.1:8547:8547"' $G/compose.yaml && echo "  ok: published on 127.0.0.1 only"
echo "lint passed"
