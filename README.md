# IPTF PoCs

Proof of concept implementations for [IPTF](https://iptf.ethereum.org).

> **Warning:** These are research prototypes, not production-ready code. Do not use in production without thorough security audits.

## Structure

```
pocs/
  [project-name]/       # Self-contained PoC
    REQUIREMENTS.md     # Actionable requirements from use case + approach
    SPEC.md             # Protocol specification (main deliverable)
    README.md           # Build/run instructions, limitations
    [approach-1]/       # For multi-approach PoCs
      SPEC.md
      README.md
    [approach-2]/
      ...
docs/
  CONTRIBUTING.md       # PR guidelines
CHANGELOG.md            # Repository-wide change history
```

Each PoC is independent—own language and tooling. No shared dependencies between projects.

## PoCs

| Name | Privacy Primitive | Status |
|------|-------------------|--------|
| [private-bond](./pocs/private-bond/) | Confidential bond transfers | In Progress |
| [approach-private-trade-settlement](./pocs/approach-private-trade-settlement/) | Confidential atomic DvP settlement | Draft |

## Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for PR guidelines. Use [pocs/_template](pocs/_template) when adding new PoCs.

## See Also

- [iptf-map](https://github.com/ethereum/iptf-map) — Mapping of privacy primitives
