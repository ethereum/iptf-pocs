# Changelog

All notable changes to this repository are documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/). Since this is a PoC repository (not versioned releases), entries are organized by date.

## How to Update

When making changes, add an entry under the appropriate date heading:

```markdown
## YYYY-MM-DD

### [poc-name] or [repo]
- **Added**: New features or files
- **Changed**: Modifications to existing functionality
- **Fixed**: Bug fixes
- **Removed**: Deleted features or files
```

Use `[repo]` for repository-wide changes (CI, templates, docs).

---

## Unreleased

### [private-bond]
- Pending: `fhe` approach

---

## 2025-01-26

### [private-bond]
- **Added**: `custom-utxo` approach — EVM-based UTXO model with Noir ZK circuits
- **Added**: `privacy-l2` approach — Aztec L2 native privacy implementation
- **Added**: Shared `REQUIREMENTS.md` derived from iptf-map use case

### [repo]
- **Added**: Project documentation (`CLAUDE.md`, `CONTRIBUTING.md`)
- **Added**: PoC template structure in `pocs/_template/`
- **Added**: CI workflow for structure validation
