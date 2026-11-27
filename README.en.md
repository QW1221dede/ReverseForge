# ReverseForge

A local-first reverse engineering & security analysis workbench for Windows:
drag any file (APK / DEX / PE / ELF / Electron asar / scripts) in, identify it,
analyze auth-checkpoints, auto-decrypt, patch, rebuild & re-sign — all offline.

> For learning, research, and **authorized** testing only. Do NOT use it to
> bypass licensing of software you don't own. See [DISCLAIMER.md](DISCLAIMER.md).

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
