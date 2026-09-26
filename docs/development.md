# Development

## Setup

```sh
uv sync --group dev
make check
```

`make check` runs the full local gate: ruff lint and format, bandit,
mypy strict, ty, and pytest with coverage. The test phase builds the
Cython accelerator in place, runs the suite against it, then re-runs
with `CBORX_DISABLE_FAST=1` to cover the pure-Python backend.

## Docs

The documentation is built with [Zensical](https://zensical.org) and
lives in `docs/`.

```sh
uv sync --only-group docs
uv run zensical serve   # local preview with live reload
uv run zensical build   # static site into site/
```

Pushes to `master` that touch `docs/`, `zensical.toml` or the docs
workflow deploy the site to GitHub Pages automatically.

## Conventions

- No runtime dependencies unless the project genuinely needs one.
- Source files start with the SPDX license identifier.
- Public API changes need tests.
- Commit messages follow conventional commits with a short subject:
  `feat(scope): ...`, `fix(scope): ...`, `test(scope): ...`,
  `chore(scope): ...`, `docs(scope): ...`, `perf(scope): ...`.

Report bugs through GitHub issues. Security reports go to
security@quad4.io.

License: 0BSD. Quad4 Software, https://quad4.io
