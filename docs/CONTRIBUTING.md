# Contributing

## Getting Started

1. Fork the repository
2. Create a feature branch from `master`
3. Make your changes
4. Submit a pull request

### PoC Creation

1. Create a folder in `pocs/` and `cd` into it
2. Build `REQUIREMENTS.md` and `README.md`
3. Create a folder with the name of the approach and `cd` into it
4. Run `cargo generate --path ../../_template --init` and follow the prompts

## Pull Request Guidelines

- Keep PRs focused on a single change
- Write clear commit messages
- Ensure CI passes before requesting review
- Link related issues in the PR description

## PR Template

```
## Summary
<!-- Brief description of changes -->

## Related Issues
<!-- Link any related issues: Fixes #123 -->

## Testing
<!-- How were these changes tested? -->

## Checklist
- [ ] CI passes
- [ ] Documentation updated (if applicable)
```

## Questions?

Open an issue for discussion before starting large changes.
