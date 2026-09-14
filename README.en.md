# ProxyDuck — Per-Application Proxy Routing & Diagnostics for Windows

[简体中文](README.md) | [English](README.en.md)

ProxyDuck transparently routes TCP and UDP traffic from selected Windows applications through local SOCKS5 proxy endpoints. With a desktop interface, a Windows background service, and a complete CLI, you can configure process routing rules, simulate policies, diagnose network health, and inspect real-time matches without modifying application binaries.

You must provide a local SOCKS5 endpoint from Clash, sing-box, V2Ray, or another proxy client. **ProxyDuck does not provide proxy servers or replace your proxy service.**

[Download v1.1.0](https://github.com/rowanjove/ProxyDuck/releases/tag/v1.1.0) · [Changelog](CHANGELOG.md) · [Report an issue](https://github.com/rowanjove/ProxyDuck/issues)

## Interface Overview

### Dashboard
Real-time routing toggle, active rule status, matched processes, and recent activity logs.
![ProxyDuck dashboard with routing controls, rules, and recent activity](docs/images/proxyduck-overview.png)

### Rule Workbench
Match applications by process name, full path, PID (with creation-time verification), or wildcards. Includes rule grouping, tags, batch operations, and pre-built templates.
![ProxyDuck per-application routing rules](docs/images/proxyduck-rules.png)

### Network Doctor
10-layer network and proxy diagnostics covering adapters, gateways, routes, DNS, NCSI probes, Winsock catalog, Hosts, and dead proxy ports. Includes safe one-click repair and instant snapshot rollback.
![ProxyDuck 10-layer network diagnostics and repair](docs/images/proxyduck-doctor.png)

<sub>Screenshots use loopback proxy addresses and an isolated test configuration without real user data.</sub>

## Key Capabilities

- **Process-Level Routing**: Route specific applications without changing global Windows proxy settings.
- **Multiple Engines**: Built-in ProxiFyre (WinpkFilter packet redirection driver) with optional sing-box TUN backend.
- **Network Doctor**: Automated 10-layer diagnostics and safe rollback snapshots before any network remediation.
- **Policy Simulator (Studio)**: Analyze rule evaluation chains, detect dead rules, shadowed rules, and test routing decisions before applying.
- **Profiles V1**: Save, clone, diff, and switch configuration snapshots for work, development, or gaming.
- **Endpoint Import**: Safely import local Clash `proxies` and sing-box `outbounds` configs with preview verification and credential redaction.
- **Windows Service Host**: Runs unattended via `proxyduck-service.exe` and communicates through ACL-protected Named Pipes for privilege minimization.
- **Credential Protection**: DPAPI-encrypted secrets, redacted config exports, and structured diagnostics bundles.

## Install and Configure

Requires Windows 10/11 x64, WebView2 Runtime, and an active local SOCKS5 proxy. Driver installation and service registration require administrator privileges.

1. Download from [Releases](https://github.com/rowanjove/ProxyDuck/releases):
   - `ProxyDuck-1.1.0-setup.exe`: Installer that automatically registers the Windows Service and WinpkFilter driver; desktop app runs with standard user rights.
   - `ProxyDuck-1.1.0-portable.zip`: Portable package; run `drivers\Install-WinpkFilter.cmd` once before first use.
2. Start your proxy application and confirm its SOCKS5 port (e.g. `127.0.0.1:7897`).
3. Add the endpoint in Proxies and test connectivity.
4. Add rules in Rules for your target applications.
5. Enable routing on the Overview page and verify data-plane status.

ProxyDuck binaries do not currently have a commercial code signing certificate and may trigger Windows SmartScreen. Bundled third-party runtimes come from pinned upstream releases verified by SHA-256.

## Command Line (CLI)

Run from the package directory:

```powershell
# Check overall status
.\proxyduck-cli.exe status

# Toggle routing
.\proxyduck-cli.exe runtime on
.\proxyduck-cli.exe runtime off

# Switch engine
.\proxyduck-cli.exe mode set proxifyre

# List proxies & preview local config import
.\proxyduck-cli.exe proxies list
.\proxyduck-cli.exe proxies import .\clash.json
.\proxyduck-cli.exe proxies import .\clash.json --apply

# Rules and profiles management
.\proxyduck-cli.exe rules list
.\proxyduck-cli.exe profiles list
.\proxyduck-cli.exe profiles create "Dev"
.\proxyduck-cli.exe profiles diff <profile-id>

# Processes and logs
.\proxyduck-cli.exe processes list --filter code --limit 20
.\proxyduck-cli.exe logs --tail 50
```

When the service is installed, the CLI automatically communicates over Named Pipes. Otherwise, it connects to `http://127.0.0.1:46666`.

## Build from Source

Requires Rust stable, Node.js 20+, Visual Studio 2022 C++ Build Tools, and Windows 10/11 x64.

```powershell
npm install
npx playwright install chromium
.\scripts\verify-release.ps1
.\scripts\build-release.ps1
.\scripts\package-release.ps1
```

## History, Contributions, and Licensing

ProxyDuck was formerly **SmartFlow**; versioning restarts at 1.0.0. Source code is licensed under the [MIT License](LICENSE). Third-party runtimes retain their respective upstream licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [THIRD_PARTY_SOURCES.md](THIRD_PARTY_SOURCES.md).
