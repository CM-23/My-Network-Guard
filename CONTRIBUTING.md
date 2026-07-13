# Contributing to My Network Guard

Thank you for your interest in contributing! Please follow these guidelines.

---

## Getting Started

1. Fork the repository and clone your fork
2. Install dev dependencies:
   ```bash
   make install-dev
   ```
3. Verify tests pass:
   ```bash
   make test
   ```

---

## Development Workflow

1. **Create a branch**: `git checkout -b feature/your-feature-name`
2. **Write code** following the style guide below
3. **Add tests** — all new features must include unit tests
4. **Run the test suite**: `make test`
5. **Run linting**: `make lint`
6. **Format code**: `make format`
7. **Submit a PR** using the pull request template

---

## Code Style

- **Formatter**: Black (`make format`)
- **Line length**: 120 characters
- **Import order**: isort with Black profile
- **Type hints**: Required for all public functions
- **Docstrings**: Required for all public classes and functions

---

## Testing Requirements

- All new features must include **unit tests** in `tests/unit/`
- All new API endpoints must include **integration tests** in `tests/integration/`
- Security-sensitive features must include **OWASP tests** in `tests/security/`
- Minimum test coverage: **70%** on new code

---

## Security Requirements for PRs

Before submitting, verify:
- [ ] No secrets hardcoded anywhere
- [ ] All user inputs validated via `shared/validators.py`
- [ ] All SQL queries parameterized (no string concatenation)
- [ ] Any new URL inputs include SSRF protection
- [ ] Auth required on all mutating endpoints
- [ ] Audit log written for state-changing operations

---

## Branch Naming

- `feature/description` — New features
- `fix/description` — Bug fixes
- `security/description` — Security improvements
- `docs/description` — Documentation only

---

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):
```
feat: add lateral movement detection
fix: correct ARP spoofing false positive for proxy ARP
security: strengthen webhook SSRF validation
docs: update API reference for v1 endpoints
```

---

## Architecture Notes

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full architecture documentation before making structural changes.
