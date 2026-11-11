# vault-plugin-secrets-featbit

Go Vault secrets engine for FeatBit. Source of truth: `docs/spec.md` (read it before changing behavior).

## FeatBit reference
Local fork checkout: `/home/rbrennan/source/public-forks/featbit` (back end in `modules/back-end`, evaluation server alongside).
It is an upstream fork — read it freely, but do not modify it, commit to it, or push/PR from it from this project. Fork changes listed in the spec (e.g. `[OpenApi]` attributes, `ExpiresAt`) are done separately in that repo, on a feature branch.

## Layout
Follows spec "Code structure": root package `featbitplugin` (backend, path_*, secret_cred, sweep), `featbit/` (client interface, HTTP impl, fake), `cmd/vault-plugin-secrets-featbit/main.go`.

## Rules
- Unit tests use the fake client only; anything hitting a real FeatBit/Vault is an integration test.
- Never log or return secrets/tokens or FeatBit response bodies; raw `Authorization` header (no `Bearer`); never retry POST; TLS always verified.
- Next step: milestone 1 spikes (open questions in spec), then milestone 2 skeleton.
