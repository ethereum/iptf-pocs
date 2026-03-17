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

| Name | Privacy Primitive | Approaches | Status |
|------|-------------------|------------|--------|
| [private-payment](./pocs/private-payment/) | Confidential stablecoin transfers | Shielded Pool (Noir), Plasma (Intmax2) | Complete |
| [private-bond](./pocs/private-bond/) | Confidential bond transfers | Custom UTXO (Noir), Privacy L2 (Aztec), FHE (Zama) | Complete |
| [private-trade-settlement](./pocs/private-trade-settlement/) | Confidential atomic DvP | TEE Swap | Complete |
| [diy-validium](./pocs/diy-validium/) | Confidential institutional payments | Validium (RISC Zero) | Active |

## Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for PR guidelines. Use [pocs/_template](pocs/_template) when adding new PoCs.

## See Also

- [iptf.ethereum.org](https://iptf.ethereum.org/) — Writeups and documentation
- [iptf-map](https://github.com/ethereum/iptf-map) — Mapping of privacy primitives
