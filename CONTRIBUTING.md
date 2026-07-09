# Contributing

Thanks for helping improve BeyondLabs. Keep contributions scoped, practical, and aligned with the project goal: a local cybersecurity/SOC workspace with honest, evidence-aware outputs.

## Workflow

1. Create a focused branch from the current main branch.
2. Make small, reviewable changes.
3. Run the relevant checks before opening a pull request.
4. Include screenshots for visible frontend changes when practical.

Suggested branch names:

- `fix/short-description`
- `feat/short-description`
- `docs/short-description`
- `chore/short-description`

## Pull Request Expectations

Pull requests should include:

- A focused scope.
- A clear summary of what changed.
- Testing notes with commands run and results.
- Screenshots only for UI changes.
- Security impact notes for security-sensitive changes.
- Any known limitations or follow-up work.

Do not mix unrelated cleanup, redesign, backend behavior changes, and feature work in one PR.

## Required Checks

Frontend changes:

```bash
cd frontend
npm run lint
npm run build
```

Backend changes:

```bash
cd backend
python -m compileall app
```

## Security Expectations

- Do not hardcode secrets, API keys, provider tokens, or credentials.
- Do not commit real case data, malware samples, private IOCs, scan outputs, or customer/client data.
- Do not fake or mock successful security results.
- Do not add unsafe active scanning defaults.
- Do not auto-upload user data to third-party services.
- Keep external enrichment opt-in and clear about source, method, confidence, limitations, and collection time.

## Repository Hygiene

Before making the repository public, review scripts, configuration files, and environment examples for private workflow details or sensitive data. Do not expose secrets, private paths, local-only credentials, real case data, or sensitive workflow metadata.
