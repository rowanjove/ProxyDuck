# Third-Party Notices

ProxyDuck source code in this repository is licensed under the MIT License.
Official Windows x64 packages include the unmodified third-party runtimes below;
those components keep their own licenses. Exact asset URLs, versions, sizes, and
SHA-256 hashes are recorded in `DEFAULT-RUNTIMES.json`. Full license texts are
included in the package's `licenses` directory, and exact source links are in
`THIRD_PARTY_SOURCES.md`.

## ProxiFyre

- Upstream project: `wiresock/proxifyre`
- Upstream repository: <https://github.com/wiresock/proxifyre>
- Bundled version: `2.4.0` x64 signed release
- Upstream license: `AGPL-3.0-only`

The ProxyDuck MIT license does not apply to ProxiFyre binaries or source code.
ProxyDuck downloads the pinned official release during packaging, verifies its
SHA-256, and redistributes it unmodified as a separate executable and libraries.

The ProxiFyre release also contains the following upstream libraries:

- Newtonsoft.Json `13.0.3` — MIT
- NLog `5.2.3` — BSD-3-Clause
- Topshelf `4.3.0` — Apache-2.0

Their license texts are included alongside the ProxiFyre license.

## Windows Packet Filter (WinpkFilter / NDISAPI)

- Upstream project: `wiresock/ndisapi`
- Upstream repository: <https://github.com/wiresock/ndisapi>
- Bundled version: `3.6.2.1` x64 MSI from the `v3.6.2` release
- Upstream license: `MIT`

WinpkFilter is the driver dependency used by ProxiFyre. The Windows installer
installs the bundled, hash-verified MSI. The portable package includes the same
MSI and a local installation helper in its `drivers` directory. Because the
driver can be shared by other applications, uninstalling ProxyDuck does not
automatically remove WinpkFilter.

## sing-box

- Upstream project: `SagerNet/sing-box`
- Upstream repository: <https://github.com/SagerNet/sing-box>
- Upstream license: `GPL-3.0-or-later` with an additional naming restriction

sing-box remains an optional external runtime and is not included in normal
ProxyDuck packages. Users may install it themselves, point ProxyDuck to it with
`PROXYDUCK_SING_BOX_PATH`, or explicitly build with `-BundleSingBox` after
reviewing its license and redistribution obligations.
