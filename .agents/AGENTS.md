# Agent Rules for `go-tunnel`

## Language & Coding Style Policies
- **Communication Language**: AI must communicate with the user (chat, explanations, plans, questions, and replies) in **Indonesian** (Bahasa Indonesia).
- **Codebase Language**: All code modifications, comments, documentation, method names, variables, class names, functions, and database structures must be written in **English**.

## Commands Policy
- Use `make test` instead of `go test`.
- Use `make lint` instead of `golangci-lint`.
- Use `make build` instead of `go build`.

## Git commit message format (Conventional Commits + Semantic Versioning)

### Format

```
<type>[optional scope]: <subject>

[optional body]

[optional footer]
```

### Type

Type must be one of the following:

- `feat`: new feature
- `fix`: bug fix
- `docs`: documentation
- `style`: formatting (whitespace, semicolons, etc.)
- `refactor`: code refactoring
- `perf`: performance improvement
- `test`: test improvements
- `build`: build system or dependency changes
- `ci`: CI configuration or scripts
- `chore`: maintenance or tooling
- `revert`: revert previous commit
- `improvement`: improve existing feature

### Scope

Scope is optional and should be the name of the module or component being changed (e.g., `api`, `client`, `tunnel`).

### Subject

Subject must be in imperative mood and start with a lowercase letter.

### Body

Body is optional and should provide additional context about the change.

### Footer

Footer is optional and can contain:
- `BREAKING CHANGE`: if the commit introduces breaking changes
- `Closes #<number>`: if the commit closes an issue

### Examples

```
feat(client): add support for SSH tunnels

This commit introduces support for SSH tunnels in the client.

BREAKING CHANGE: The client now requires an SSH server to be running.
```

```
fix(api): resolve authentication issue

Fixes an authentication issue that caused 401 errors.
```

### Validation

Before pushing, validate that the commit message follows the format by running:

```bash
git log -1 --pretty=format:"%B" | grep -E "^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([a-z0-9_-]+\))?: .+$"
```

## Changelog Policy
- **Record Changes**: Whenever a new feature (`feat`), improvement (`improvement`), or bug fix (`fix`) is completed, the agent **MUST** update `CHANGELOG.md` in the project root.
- Add the title and brief description under the `## [Unreleased]` section categorized by `### Added`, `### Changed`, or `### Fixed`. This ensures all changes are properly tracked for future release changelogs.

## Release Documentation Policy
- **Concise & Categorized Release Notes**: When generating release documents or GitHub release notes, keep the output **as concise as possible** using concise 1-line bullet points. Exactly categorize changes under clear sections: `## 🚀 New Features`, `## ⚡ Enhancements & Changes`, and `## 🐛 Bug Fixes & Security`. Avoid lengthy multi-paragraph explanations.
