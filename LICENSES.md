# Third-Party Licenses & Release Verification

`netdoctor` orchestrates external upstream binaries and community lists without embedding GPL source code inside the Python library. All downloaded artifacts are tracked with fixed SHA-256 hashes in [bin/manifest.json](bin/manifest.json) and verified via `netdoctor fetch-bins --verify-only`.

## Upstream Components

| Component | Repository | License | Usage in `netdoctor` |
|---|---|---|---|
| `winws2` & `blockcheck2` | `bol-van/zapret-win-bundle` | MIT (zapret) | External DPI desync process (`bin/winws2.exe`) and analyzer scripts (`bin/blockcheck/`) |
| `tg-ws-proxy` | `Flowseal/tg-ws-proxy` (`v1.11.4`) | MIT (`bin/tg-ws-proxy/LICENSE`) | Local MTProto WebSocket proxy launched as a subprocess |
| Seed lists & presets | `Flowseal/zapret-discord-youtube` (`1.10.4`) | MIT | Domain lists (`lists/*.txt`), payload blobs (`bin/files/*.bin`), reference presets |
| `byedpi` (`ciadpi.exe`) | `hufrea/byedpi` (`v0.17.3`) | MIT | Backup local SOCKS5 DPI bypass process (`bin/ciadpi.exe`) |
| `sing-box` | `SagerNet/sing-box` (`1.14.4`) | GPL-3.0-or-later (with non-endorsement / naming restriction) | Executed strictly as an external binary (`bin/sing-box.exe`) over generated `configs/sing-box.json` |

## Integrity & Mirroring Policy
- Every downloaded artifact's byte size and SHA-256 digest is recorded in `bin/manifest.json`.
- `netdoctor fetch-bins --verify-only` validates PE headers (`MZ`), presence of companion files, and SHA-256 digests against `bin/manifest.json` before execution.
- Source code and release artifacts should be mirrored across independent Git hosts with pinned release tags and SHA-256 checksums.
