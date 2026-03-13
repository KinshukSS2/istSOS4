documentation and other files), the included "makefiles" tell the build system to
to install dependencies and compile GRASS source code for most operating systems.
# Contributing

Thanks for your interest in contributing to istSOS4.

## Ways to contribute

- Report bugs and feature requests: <https://github.com/istSOS/istSOS4/issues>
- Improve API code in `api/`
- Improve SQL schema and migrations in `database/`
- Improve docs and tutorials in `docs/`

## Development setup

1. Fork and clone the repository.
2. Copy environment variables:
	```sh
	cp .env.example .env
	```
	If `.env.example` is not present in your branch yet, create `.env` from project documentation and existing defaults.
3. Start local services:
	```sh
	docker compose -f dev_docker-compose.yml up -d
	```

## Code changes

- Keep changes focused and minimal.
- Follow existing project patterns and naming conventions.
- Update documentation when behavior or configuration changes.
- Avoid unrelated refactors in the same pull request.

## Testing

Run relevant tests locally before opening a pull request.

Examples:

```sh
cd api
PYTHONPATH=/home/deadpool/ist/istSOS4/api python -m unittest app.sta2rest.test -v
python -m pytest -q
```

If you add a fix for a specific bug, include a focused regression test when possible.

## Pull requests

- Use a clear branch name (for example `fix/<short-description>`).
- Keep commit messages short and descriptive.
- Include:
  - Problem summary
  - Root cause
  - What changed
  - How you tested it (terminal output or test command)

## Security and sensitive data

- Never commit secrets or private credentials.
- Keep `.env` out of git.
- Use safe defaults for local development only.

Thanks for helping improve istSOS4.
