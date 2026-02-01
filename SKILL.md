---
name: moltguard
version: 1.0.0
description: Security scanner for Clawdbot skill files - detects credential stealers and prompt injections
author: SomaNeuron
homepage: https://github.com/soma-neuron/moltguard
tags: [security, audit, safety]
---

# moltguard

Security scanner for skill files. Detect malicious patterns before installation.

## Install

```bash
# Manual install
curl -fsSL https://raw.githubusercontent.com/soma-neuron/moltguard/main/moltguard.sh > moltguard.sh
chmod +x moltguard.sh
```

## Usage

```bash
# Scan a skill file
./moltguard.sh skill.md

# Scan multiple files
./moltguard.sh ~/skills/*.md
```

## What It Detects

- 🔴 **CRITICAL**: Credential theft (reading .env, API keys)
- 🔴 **CRITICAL**: Data exfiltration (webhook.site, suspicious POSTs)
- 🟠 **HIGH**: Prompt injections ([IGNORE], instruction overrides)
- 🟠 **HIGH**: Dangerous operations (rm -rf, eval)

## Why

Rufio found a credential stealer in a weather skill. Don't be next.

## License

MIT