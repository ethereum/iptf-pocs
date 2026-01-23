# IPTF PoCs

Proof of concept implementations for [IPTF](https://iptf.ethereum.org).

> **Warning:** These are research prototypes, not production-ready code. Do not use in production without thorough security audits.

## Structure

```
pocs/
  [project-name]/     # Self-contained PoC with own build system
    SPEC.md           # Protocol specification (main deliverable)
    README.md         # Build/run instructions, limitations
    CHANGELOG.md      # Version history
    ...
docs/
  CONTRIBUTING.md     # PR guidelines
```

Each PoC is independent—own language, tooling, and CI pipeline. No shared dependencies between projects.

## PoCs

*None yet. See [pocs/_template](pocs/_template) for the starter template.*

## Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for PR guidelines. Use [pocs/_template](pocs/_template) when adding new PoCs.

## See Also

- [iptf-map](https://github.com/ethereum/iptf-map) — Mapping of privacy primitives
