# ProxyDuck — Per-application proxy routing for Windows

[简体中文](README.md) | [English](README.en.md)

ProxyDuck routes TCP, UDP, and DNS traffic from selected Windows applications through a local SOCKS5 proxy. Its desktop interface and CLI let you configure process rules, test proxy connectivity, inspect routing status, and review recent matches.

You must provide a local SOCKS5 endpoint from Clash, sing-box, V2Ray, or another proxy application. **ProxyDuck does not provide proxy servers or replace your proxy service.**

[Download v1.0.0](https://github.com/rowanjove/ProxyDuck/releases/tag/v1.0.0) · [Changelog](CHANGELOG.md) · [Report an issue](https://github.com/rowanjove/ProxyDuck/issues)

![ProxyDuck dashboard with routing controls, rules, and recent activity](docs/images/proxyduck-overview.png)

## Install and configure

Requires Windows 10/11 x64, WebView2 Runtime, and a working local SOCKS5 proxy. Driver installation and traffic interception require administrator privileges.

1. Download from [Releases](https://github.com/rowanjove/ProxyDuck/releases):
   - `ProxyDuck-1.0.0-setup.exe`: installer that deploys the WinpkFilter driver.
   - `ProxyDuck-1.0.0-portable.zip`: portable package; run `drivers/Install-WinpkFilter.cmd` before first use.
2. Start your proxy application and confirm its SOCKS5 port, for example `127.0.0.1:7897`.
3. Add the endpoint in Proxies and test connectivity.
4. Select an application, target proxy, and protocols in Rules.
5. Enable routing in Overview, then check data-plane status and actual matches.

ProxyDuck binaries do not currently have commercial code signing and may trigger SmartScreen. Bundled third-party runtimes come from pinned upstream release assets verified by SHA-256. Uninstalling ProxyDuck does not automatically remove WinpkFilter, which other applications may share.

## Rules and status

- Match applications by process name, full path, PID, or wildcard.
- Apply rule-order priority, with conflict checks, copying, reordering, and process dry runs.
- Configure TCP, UDP, and DNS interception separately.
- Inspect core, data-plane, proxy-connectivity, and leak-protection status separately. A reachable proxy port does not prove that all application traffic is being routed.
- Use single-instance operation, the system tray, Chinese/English interfaces, and light/dark themes.

![ProxyDuck per-application routing rules](docs/images/proxyduck-rules.png)

Screenshots use loopback proxy addresses and an isolated demo configuration without real user data.

## Data planes and limitations

| Component | Default status | Purpose |
| --- | --- | --- |
| ProxiFyre 2.4.0 x64 | Bundled | Forward target-process TCP/UDP to SOCKS5 |
| WinpkFilter 3.6.2.1 x64 | Bundled | Packet-filter driver required by ProxiFyre |
| sing-box TUN | User-installed | Optional data plane |
| Native WFP | Not available | Requires an independently signed driver |
| API Hook | Experimental | Not a delivered capability |

Pinned versions, sources, and hashes are in [default-runtimes.json](third_party/default-runtimes.json). Packaging generates `RUNTIME-LOCK.json` to verify runtime files in release packages.

The desktop app and CLI call Core through a local API. Core discovers processes, compiles rules, and controls the data plane, which forwards traffic to a SOCKS5 endpoint. Configuring a rule in the interface does not replace validation of each engine's behavior and limits.

## Command line

Run from the extracted package directory:

```powershell
.\proxyduck-cli.exe status
.\proxyduck-cli.exe runtime on
.\proxyduck-cli.exe runtime off
.\proxyduck-cli.exe mode set win-divert
.\proxyduck-cli.exe proxies list
.\proxyduck-cli.exe rules list
.\proxyduck-cli.exe processes list --filter code --limit 20
.\proxyduck-cli.exe logs --tail 50
```

`mode set win-divert` is the current CLI identifier for selecting the default ProxiFyre data plane. The CLI connects to `http://127.0.0.1:46666` by default; use `--core-url` for another local address.

## Local data and security

Core API listens locally and authenticates with a random token protected by the current Windows user's DPAPI. The application data directory contains `config.json5`, `token`, `core.log`, and `crash.log`. Configuration and logs can include proxy or process information; review and redact them before sharing.

Common environment variables:

- `PROXYDUCK_CORE_URL`: Core API address.
- `PROXYDUCK_PROXIFYRE_DIR`: custom ProxiFyre directory.
- `PROXYDUCK_SING_BOX_PATH`: user-installed sing-box path.
- `PROXYDUCK_ICON_DIR`: process icon cache directory.

First launch migrates ProxyDock and older SmartFlow configuration without deleting the old directories.

## Build from source

Requires Rust stable, Node.js 20+, Visual Studio 2022 C++ Build Tools, and Windows 10/11 x64.

```powershell
git clone https://github.com/rowanjove/ProxyDuck.git
cd ProxyDuck
npm ci
npx playwright install chromium
./scripts/verify-release.ps1
./scripts/build-release.ps1
./scripts/package-release.ps1
```

The build downloads and verifies pinned ProxiFyre, WinpkFilter, and license texts. Runtime caches are not committed to Git. sing-box is not downloaded by default. To build a custom bundle:

```powershell
./scripts/build-release.ps1 -BundleSingBox -SingBoxPath "C:/path/to/sing-box.exe"
```

## History, contributions, and licensing

ProxyDuck was previously SmartFlow; public releases restart at 1.0.0. The old repository is a private historical archive. Some `smartflow-*` source directories remain for compatibility with existing scripts.

[Roadmap](ROADMAP.md) · [Contribution guide](CONTRIBUTING.md) · [Security reports](SECURITY.md)

Supporting guides are primarily in Chinese. Project-owned source uses the [MIT License](LICENSE). MIT does not cover bundled ProxiFyre or other third-party runtimes; read the [third-party notices](THIRD_PARTY_NOTICES.md) and [corresponding source references](THIRD_PARTY_SOURCES.md) before redistribution.
