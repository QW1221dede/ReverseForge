# ReverseForge

A local-first reverse engineering & security analysis workbench for Windows:
drag any file (APK / DEX / PE / ELF / Electron asar / scripts) in, identify it,
analyze auth-checkpoints, auto-decrypt, patch, rebuild & re-sign — all offline.

> For learning, research, and **authorized** testing only. Do NOT use it to
> bypass licensing of software you don't own. See [DISCLAIMER.md](DISCLAIMER.md).

> ### Restricted modules — not available in the public build
>
> Under the laws of the People's Republic of China, three capability classes —
> **live packet transmission to third-party servers, on-device injection, and
> deploying license bypasses** — ship in **encrypted form** and will not run
> without authorization.
>
> To request access, email the author with your use case and legal basis.
> Once reviewed, a **machine-fingerprint-bound key** is issued.
>
> **Email: m358685@163.com**
>
> Static analysis, unpacking, decompilation, decryption, string extraction and
> plan generation remain **fully available without authorization**.

## Features
- Full-auto pipeline: unpack -> decrypt -> remove pre-run license checks -> rebuild & sign -> drop result to Desktop
- Cross-type auth checkpoint scanning (callbacks, string gates, server re-validation)
- Auto decryption (XOR / RC4 / AES / TEA / XXTEA / OpenSSL Salted, known-plaintext attack)
- Code blocks & AI API orchestration (local HTTP API, works with any LLM)

## License
**GNU AGPL-3.0** with additional terms: **commercial use is prohibited**.
Any derivative (including network services) must stay AGPL-3.0 open-source
with these terms. See [LICENSE](LICENSE).

**Donation (optional)**: if this tool helps you, you can email the author at m358685@163.com to arrange support. Donations are voluntary and unlock nothing; every feature stays free and open-source.


## v12: Embedded-object carving

Formats whose "unpacking" differs from generic extraction are now handled
natively: vdex/oat/odex embedded DEX extraction, packed-APK DEX recovery from
lib/*.so, encrypted-zip weak-password auto fallback, and a universal carving
layer (zip/dex/cdex/ELF/gzip/xz/bzip2/7z/rar/png/jpg/pdf/sqlite/zstd) that
scans byte streams without relying on a header at offset 0. Entry points:
`rf.carve()` or script 18.

> Feedback in Chinese only: m358685@163.com (English not accepted).
