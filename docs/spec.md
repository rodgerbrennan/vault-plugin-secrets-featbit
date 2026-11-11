# Spec: vault-plugin-secrets-featbit

Nov 11, 2026 · @Rodger Brennan

## Overview

`vault-plugin-secrets-featbit` is a Go Vault secrets engine that issues short-lived FeatBit environment SDK secrets and Service access tokens on demand, and deletes them when the Vault lease ends. It drives FeatBit's management API; the evaluation server only changes if you add the optional expiry check.

**Goals**

- Scenario 1: each server-side workload gets its own leased env SDK secret (type `server`) instead of the shared static one.
- Scenario 2: a small, explicitly provisioned set of integrations (for example a partner or an automation job) each get a leased Service access token with a scoped permission set. Service tokens carry wide permissions in FeatBit, so this is the exception, not the default: an operator creates each `service_token` role by hand, for a named consumer, and grants Vault access to that role individually.
- Every credential is revoked on lease expiry or explicit revoke, and none outlives its lease by more than the propagation window (see Credential lifecycle).
- Every FeatBit-side credential name carries the Vault request ID, so FeatBit's UI and Vault's audit log cross-reference.

**Non-goals**

- Issuing Service access tokens per workload, per client or on demand at scale. Service tokens are rare and deliberately provisioned; workloads that only need to evaluate flags use scenario 1.
- Per-client leasing of client SDK secrets. They ship inside browsers and mobile apps, so a lease adds little; give them scheduled rotation with overlapping secrets, or leave them static.
- Stateless signed secrets (HMAC or JWT checked by the evaluation server). That is a possible phase 2 and a much larger fork change.
- Managing flags, projects or environments.

**Prerequisite in the fork:** FeatBit's API currently refuses access-token authentication on the secret and access-token endpoints, so the plugin cannot call them until the fork opts them in (see Fork changes).

## Architecture

&#91;embedded content: architecture · Vault mounts, FeatBit API, evaluation server\]

Workloads read credentials from Vault. Each mount creates and deletes the matching FeatBit object with its own admin token, and workloads then present the credential to FeatBit: the service token to the API server, the SDK secret to the evaluation server, which looks it up through the store behind a 30-second cache.

## FeatBit API surface

The plugin needs four calls: create and delete an env secret, create and delete a Service access token. Everything below was read from the FeatBit repo (`modules/back-end`); confirm response envelope field names against a live response before coding the client.

| Purpose | Method and path | Request body | Permission checked |
| --- | --- | --- | --- |
| Create env secret | `POST /api/v1/envs/{envId}/secrets` | `{name, type}` with type `server` or `client` | `CreateEnvSecret` |
| Delete env secret | `DELETE /api/v1/envs/{envId}/secrets/{id}` | none | `DeleteEnvSecret` |
| Create access token | `POST /api/v1/access-tokens` | `{name, type: "Service", permissions: PolicyStatement[]}` | `ManageServiceAccessTokens` |
| Delete access token | `DELETE /api/v1/access-tokens/{id}` | none | `ManageServiceAccessTokens` |
| Soft revoke (optional) | `PUT /api/v1/access-tokens/{id}/toggle` | none | `ManageServiceAccessTokens` |
| Orphan sweep, secrets | `GET /api/v1/projects/{projectId}/envs/{envId}` | none | read env |
| Orphan sweep, tokens | `GET /api/v1/access-tokens?name=vault-` | none | `ListAccessTokens` |

**What the calls return**

- Creating a secret returns `{id, name, type, value}`. `value` is the 44-character SDK secret: 22 characters of random header plus the base64-encoded env ID. Store `id` as the revocation handle.
- Creating an access token returns the full entity including `token` (`api-…`) and `id`. Access token names must be unique per organization, so use `vault-<requestID>`.
- Secret names only need to be non-empty.

**Authentication**

- Send the admin access token as the raw `Authorization` header value, with no ` Bearer  ` prefix. A ` Bearer  ` prefix routes the request to the JWT scheme instead.
- The API server fills in workspace and organization from the token, so no extra headers are needed.

**Blocker**

- `VerifyOpenApiApplicable` rejects access-token callers with 403 unless the action or controller carries `[OpenApi]`. Neither `EnvironmentSecretController` nor `AccessTokenController` has it today. Until the fork adds it, the plugin cannot authenticate with a token (see Fork changes).

**Propagation**

- A new secret is written to the environment, then `OnSecretAdded` upserts it in Redis and, if the Control Plane is enabled, publishes it on the control-plane topic. The evaluation server does not cache misses, so a new secret works as soon as it reaches the store.
- Revocation is bounded by the evaluation server's `SecretCache`, a fixed 30-second TTL per entry, plus any in-flight lookup.

## Plugin API

The plugin mounts three path groups: `config`, `roles/<name>` and `creds/<role>`. A role is either `env_secret` (scenario 1, many roles and high volume expected) or `service_token` (scenario 2, few roles and low volume expected, each one reviewed before it is created); `creds` reads on a role issue one credential and one lease.

**`featbit/config`** (write, read, delete)

| Field | Type | Notes |
| --- | --- | --- |
| `api_url` | string, required | FeatBit API base, for example `https://featbit-api.example/` |
| `admin_token` | string, required | Service access token used for all calls. Write-only: never returned by read. |
| `ca_cert` | string | PEM bundle to trust for the API's TLS. TLS verification is always on. |
| `request_timeout` | duration | Default `10s` |
| `max_retries` | int | Default `3`, applies to idempotent calls only |

Writing config makes one cheap authenticated call (list access tokens, page size 1) and fails if it is rejected. Reading config returns everything except `admin_token`.

**`featbit/roles/<name>`** (create, read, update, delete, list)

| Field | Applies to | Notes |
| --- | --- | --- |
| `credential_type` | both, required | `env_secret` or `service_token` |
| `env_id` | `env_secret` | Environment GUID, required |
| `secret_type` | `env_secret` | `server` (default) or `client` |
| `permissions` | `service_token` | JSON array of FeatBit policy statements, required, non-empty |
| `name_prefix` | both | Default `vault-`; the Vault request ID is appended |
| `ttl`, `max_ttl` | both | Lease durations; `ttl` defaults to 1h, `max_ttl` to 24h, both capped by Vault's mount limits |

`service_token` roles should be one per consumer, named for it (for example `partner-readonly`), with the narrowest permission set that consumer needs and a short `ttl`. Do not create a shared catch-all `service_token` role. Role writes validate the type-specific fields and reject unknown ones. Changing a role never touches credentials already issued.

**`featbit/creds/<role>`** (read)

| Role type | Response fields | Revocation handle kept in the lease's internal data |
| --- | --- | --- |
| `env_secret` | `secret`, `secret_id`, `env_id`, `secret_type` | `env_id`, `secret_id`, `name` |
| `service_token` | `token`, `token_id`, `name` | `token_id`, `name` |

```bash
vault secrets enable -path=featbit vault-plugin-secrets-featbit
vault write featbit/config api_url=https://featbit-api.example admin_token=api-...
vault write featbit/roles/payments-server \
  credential_type=env_secret env_id=<env-guid> secret_type=server ttl=1h max_ttl=24h
vault write featbit/roles/partner-readonly \
  credential_type=service_token permissions=@partner.json ttl=30m
vault read featbit/creds/payments-server
```

**Later, not in v1:** `featbit/rotate-root` (mint a replacement admin token, store it, delete the old one) and `featbit/sweep` (run the orphan reconciliation on demand).

## Credential lifecycle

The plugin never keeps a credential after issue: Vault's lease holds the FeatBit ID needed to delete it, and the secret value is returned once.

**Issue** (`creds/<role>`)

1. Load config and role; build the name `<name_prefix><vault request ID>`.
2. Write an intent record `pending/<request ID>` to plugin storage (role, env ID, name, timestamp).
3. Call FeatBit to create the secret or token. Do not retry a create that may have succeeded; a timeout leaves the intent record for the sweep to resolve.
4. Return the credential with a Vault lease: `ttl` from the role, `max_ttl` as the renewal ceiling, internal data holding the revocation handle.
5. Delete the intent record. If anything after step 3 fails, delete the new FeatBit object before returning the error.

**Renew**

- Extend the Vault lease up to `max_ttl`. No FeatBit call is needed: if the fork adds `ExpiresAt`, set it at issue time to issue time plus `max_ttl`, so renewal never has to touch FeatBit.
- Renewal after the role was deleted or changed is allowed; limits come from the lease, not the live role.

**Revoke**

- Call `DELETE` on the secret or access token. A 404 counts as success so revoke is idempotent.
- Retry timeouts and 5xx up to `max_retries` with backoff. If it still fails, return the error: Vault keeps the lease and retries revocation later.
- 401 or 403 means the admin token is bad. Return a clear error and leave the lease pending, never mark it revoked.

**Orphans.** A crash between steps 3 and 4 leaves a FeatBit object with no lease. A periodic function (primary node only) finds `pending/` records older than 5 minutes, looks the object up by its `vault-<request ID>` name, deletes it and removes the record.

**How fast revocation takes effect**

| Credential | Checked by | Effective after delete | Caveat |
| --- | --- | --- | --- |
| Env SDK secret | Evaluation server, cached by `SecretCache` | New connections: up to about 30 seconds, plus any in-flight lookup. **Open streaming connections: not affected** | Verified in the code: the secret is checked once when the WebSocket opens, so a revoked secret keeps streaming until the connection drops. See Long-lived streaming connections |
| Service access token | API server, looked up in the database on every request | Immediate | None found |

## Long-lived streaming connections

Server SDKs hold a WebSocket to the evaluation server open for hours or days. I read `Streaming/StreamingMiddleware.cs`, `RequestValidator.cs`, `Connection.cs` and `ConnectionManager.cs` to see what that means for leases.

**What the code does today**

- `RequestValidator` checks the secret once, in `ValidateAsync`, before the connection is added to `ConnectionManager`. Nothing re-checks it afterwards.
- A `Connection` keeps a reference to its `Secret` for its whole life. The message loop only handles messages such as `ping` and `data-sync`. Deleting a secret does not close sockets that were opened with it.
- Consequence: **revoking or expiring an env secret only stops new connections.** A leased secret that has been revoked keeps receiving flag updates for as long as the socket stays up. Without a fork change, the lease is not enforced for any workload that stays connected.

**Renewal and rotation are different things**

- *Renewal* (`vault lease renew`) extends the lease and keeps the same secret value. The socket is unaffected and no reconnect is needed. Workloads should renew for as long as they run.
- *Rotation* happens at `max_ttl`, where renewal stops. A new `creds` read returns a new secret, so the workload has to reconnect with it. Plan for this before `max_ttl`, not after.

**Design**

1. **Enforce expiry on open connections (fork change 4, now required for scenario 1).** `Connection` already has its `Secret`. Carry `ExpiresAt` (fork change 2) into it, and have a background service walk `ConnectionManager` every ~15 seconds and close connections past expiry. Also close a secret's connections when it is deleted, using the same delete path that fires `OnSecretAdded` in reverse. Use a distinct WebSocket close code (for example 4004, "secret expired or revoked") so SDKs and logs can tell it from the existing 4003 "invalid request".
2. **Make rotation overlap.** FeatBit allows several secrets per environment, so the workload requests its replacement at about 80% of `max_ttl`, switches to it, and lets the old lease expire or revokes it. The overlap window is the only time a workload holds two secrets.
3. **Workloads do the switch, not the plugin.** The plugin cannot reach into a running SDK. Choose one per workload: Vault Agent renders the secret to a file or env and restarts the process (`exec` or a signal) on change; the application re-creates its SDK client with the new secret; or a rolling restart is scheduled slightly under `max_ttl`. The first and third need no application changes.
4. **Size TTLs for the pattern.** Use a long `max_ttl` (24h to 7d) with a short `ttl` that Vault Agent keeps renewing, so rotation is rare and a dead Agent still lets the secret lapse within `ttl`. Clients that lose Vault entirely lose their secret at `max_ttl` at the latest, once change 4 is in.
5. **Fail safe.** When the evaluation server closes a connection with 4004 and the SDK cannot get a new secret, SDKs keep serving their last cached flag values. That degraded state is by design and should be alerted on, not retried silently.

**Without fork change 4:** revocation still works for new connections and the secret is still removed from FeatBit, but workloads that stay connected keep their access. In that case the lease is advisory for streaming workloads, and the spec should not claim otherwise.

## Security

The admin token in `config` is the most sensitive thing in the design, because it can create and delete the credentials FeatBit trusts.

- **Mount one engine per scenario.** Scenario 1 mounts use a token with only `CreateEnvSecret` and `DeleteEnvSecret` on the specific environments. The scenario 2 mount alone holds `ManageServiceAccessTokens`. A leaked scenario 1 token then cannot mint API tokens.
- **Token minting is an escalation path.** `CreateAccessToken` calls `EnsureCanManage`, which checks the caller's `ManageServiceAccessTokens` permission and, in the code I read, nothing about the permissions being granted. The scenario 2 admin token can therefore mint a token with any permissions, including one that manages tokens. Treat that mount's token as organization-admin equivalent until the fork enforces that new permissions are a subset of the caller's (see Fork changes), and confirm this in the handler before relying on it either way.
- **Role permissions are Vault-operator controlled.** Clients only read `creds/<role>`; they cannot choose permissions or environments. Protect `roles/*` write access with Vault policies as tightly as `config`.
- **Service token roles are explicitly provisioned.** Because a Service token's permissions are wide, `creds/<role>` on the `featbit-svc` mount is granted per role to named identities, never by wildcard (no `creds/*` in a Vault policy). Creating a `service_token` role is a reviewed operator action, not something workloads or automation do on their own.
- **No secret in logs or errors.** Mark `admin_token`, `secret` and `token` as sensitive in the field schemas. Never include FeatBit response bodies in errors; log status code, endpoint path and request ID only.
- **TLS always verified.** No skip-verify option; use `ca_cert` for a private CA.
- **Nothing stored but handles.** Plugin storage holds config, roles and short-lived intent records. Credential values are never persisted by the plugin.
- **Audit trail.** Names embed the Vault request ID, so a FeatBit secret or token maps to one Vault audit entry. FeatBit's own audit log will show the admin token as the creator.
- **Lease volume.** Env secrets live in one JSON column on the environment row, and every one is replicated to Redis. Set Vault lease-count quotas on each mount and keep TTLs at an hour or more, so a busy workload cannot bloat that row. This applies to the `featbit-env` mount; the `featbit-svc` mount should have a small quota, since few Service tokens should exist at any time.
- **Binary integrity.** Register the plugin with its SHA-256, keep `plugin_directory` read-only, and run Vault as a non-root user.

## Fork changes in FeatBit

One change is required for the plugin to work at all (token access to the management endpoints). One is required for scenario 1 to be enforced on streaming workloads (closing open connections). One is strongly recommended (credential expiry as a backstop if Vault is down). Keep each small and isolated, since the fork rebases onto upstream.

| # | Change | Where | Status |
| --- | --- | --- | --- |
| 1 | Add `[OpenApi]` to the secret create and delete actions, and to access-token create, delete, toggle and list. Also check that the environment GET used by the orphan sweep is already marked. | `EnvironmentSecretController`, `AccessTokenController`, `EnvironmentController` in `modules/back-end/src/Api/Controllers` | Required |
| 2 | Add nullable `ExpiresAt` to env secrets and access tokens. Accept an optional `expiresAt` on the create requests (must be in the future, capped by a configured maximum). Enforce it on use and delete expired entries on a schedule. | Back end: `Domain/Environments/Secret.cs`, `Domain/AccessTokens/AccessToken.cs`, `AddSecret.cs`, `CreateAccessToken.cs`, `OpenApiHandler.cs`, a cleanup background service. Evaluation server: `Domain/Secrets/Secret.cs`, `SecretCache.cs` and the Redis, Postgres and MongoDB stores. Redis upsert in `RedisCacheService.UpsertSecretAsync` also needs the field. | Strongly recommended |
| 3 | On access-token create, reject permissions the caller does not itself hold. | `CreateAccessTokenHandler` or `AccessTokenAuthorization` | Recommended for scenario 2 |
| 4 | Close open streaming connections when their secret is deleted or expires: carry `ExpiresAt` on `Connection.Secret`, add a background sweep over `ConnectionManager`, close on delete, and use a distinct close code (4004). | Evaluation server `Streaming/` (`StreamingMiddleware.cs`, `Connections/ConnectionManager.cs`, a new hosted service) | Required for scenario 1 to be enforced on streaming workloads (verified: secrets are only checked at connect) |

**Notes on change 2**

- Env secrets are stored as JSON inside the environment row, so they need no migration. Access tokens are a table, so they need an EF Core migration (and the MongoDB model for that provider).
- Expiry precision on the evaluation server is bounded by the 30-second `SecretCache` TTL.
- The cleanup job must delete through the existing delete-secret path, not straight from the database, so the Redis entry and control-plane message are also removed.
- Set the backstop expiry to issue time plus the role's `max_ttl`. Renewal then never needs a FeatBit call.

## Code structure, build and deployment

Build on the Vault SDK (`github.com/hashicorp/vault/sdk`: `framework.Backend`, `logical.Factory`, `plugin.ServeMultiplex`) with a small FeatBit client behind an interface, so the backend is testable without a running FeatBit.

```text
vault-plugin-secrets-featbit/
  cmd/vault-plugin-secrets-featbit/main.go   # serves the backend
  backend.go          # Factory, paths, PeriodicFunc registration
  path_config.go      # featbit/config
  path_roles.go       # featbit/roles/<name>
  path_creds.go       # featbit/creds/<role>
  secret_cred.go      # framework.Secret: Renew and Revoke
  sweep.go            # intent-record reconciliation
  featbit/client.go   # interface + HTTP implementation
  featbit/fake.go     # in-memory fake for tests
  Makefile, go.mod, README.md
```

**Storage layout** (plugin view of Vault storage, encrypted by the barrier)

| Key | Holds |
| --- | --- |
| `config` | API URL, admin token, CA, timeouts |
| `role/<name>` | Role definition |
| `pending/<request ID>` | Intent record, removed once the lease is returned |

**FeatBit client rules**

- Single `http.Client` with the configured timeout; custom `RootCAs` from `ca_cert`; no redirects followed to another host.
- Raw `Authorization: <token>` header, never `Bearer`.
- Retry only idempotent calls (`DELETE`, `GET`) on timeouts and 5xx, with jittered backoff. Never retry `POST`.
- Map FeatBit errors to Vault errors without echoing response bodies.

**Registration and deployment**

```bash
# build, then copy to every Vault node's plugin_directory
make build   # CGO_ENABLED=0 go build -o vault-plugin-secrets-featbit ./cmd/vault-plugin-secrets-featbit
vault plugin register -sha256=$(sha256sum vault-plugin-secrets-featbit | cut -d' ' -f1) \
  secret vault-plugin-secrets-featbit
vault secrets enable -path=featbit-env vault-plugin-secrets-featbit
vault secrets enable -path=featbit-svc vault-plugin-secrets-featbit
```

- The binary must be on every node in an HA cluster, with the same checksum. For a containerized Vault, bake it into the image or mount it read-only.
- After upgrading the binary, re-register with the new checksum and run `vault plugin reload`.
- Run two mounts (`featbit-env`, `featbit-svc`) with different admin tokens, as described under Security.

## Testing

The highest-risk behavior is partial failure (a credential created in FeatBit that Vault never tracks, or a revoke that silently fails), so tests concentrate there.

| Layer | How | Must cover |
| --- | --- | --- |
| Backend unit tests | `logical.TestBackendConfig` with in-memory storage and the fake FeatBit client | Role validation per credential type; issue success; FeatBit create fails (no lease); failure after create (new object deleted); renew within and past `max_ttl`; revoke on 404, on 5xx, on 401 |
| Client tests | `httptest.Server` | Raw `Authorization` header with no `Bearer`; `POST` never retried; `DELETE` retried on 5xx; no response body in errors; custom CA honored |
| Sweep tests | Fake client plus seeded `pending/` records | Orphan found by name and deleted; record older than the threshold removed; recent record left alone |
| End-to-end | Docker Compose FeatBit (the repo's standard compose file) plus a Vault dev server with the plugin | Env secret: issue, authenticate to the evaluation server, revoke, confirm new connections are rejected within about 35 seconds and an already-open WebSocket is closed with 4004 within about 50 seconds (needs fork change 4); also run a rotation: issue a second secret before `max_ttl`, reconnect, and let the first lapse. Service token: issue, call an `[OpenApi]` endpoint, revoke, confirm rejection on the next call |
| Fork tests | FeatBit's existing .NET test projects | `ExpiresAt` rejected on use and cleaned up by the job, for all three evaluation-server stores (Redis, Postgres, MongoDB) and the API-server handler |
| Failure injection | Manual script | FeatBit down during revoke then back up; Vault restarted between create and lease return; two nodes issuing at once |

**Exit criteria for v1:** the end-to-end tests pass for both credential types, and the failure-injection run leaves zero `vault-` entries in FeatBit once all leases are revoked and one sweep cycle has run.

## Milestones, open questions and risks

Build in six steps, each shippable on its own. Steps 1 and 2 retire most of the risk before any plugin code exists.

1. **Fork prerequisite and spikes.** Add `[OpenApi]` to the secret and access-token actions, then answer the open questions below against a running fork.
2. **Skeleton.** Go module, `config` and `roles` paths with validation, unit tests, registration on a dev Vault.
3. **`env_secret` credentials.** Issue, renew, revoke, intent records; end-to-end test against the evaluation server.
4. **`service_token` credentials.** Same flow, plus the subset-permission fork change.
5. **Expiry and sweep.** `ExpiresAt` in the fork, periodic orphan reconciliation, failure-injection run.
6. **Hardening.** Lease quotas, `rotate-root`, docs, a runbook for a bad admin token.

**Open questions to settle first**

- [x] Do open streaming connections survive deletion of their secret? Yes: the secret is checked only at connect (see Long-lived streaming connections), so fork change 4 is required.
- [ ] Which rotation mechanism will each scenario 1 workload use (Vault Agent restart, SDK re-create, scheduled rolling restart), and do the SDK versions in use cope with a 4004 close and a changed secret?
- [ ] Exact response envelope of the management API (`ApiResponse<T>` field names) and the URL version segment in your deployment.
- [ ] Does the `CreateAccessToken` path really skip a subset check on requested permissions? Confirm in the handler and by test.
- [ ] Which `EnvironmentController` actions already carry `[OpenApi]`, and is the env GET among them?
- [ ] Does enabling the Control Plane change how fast deletes reach the evaluation server?
- [ ] How will workloads obtain and refresh secrets (Vault Agent or CSI) and make their FeatBit SDK reconnect when a lease rolls? The plugin alone does not give scenario 1 value without this.
- [ ] Do you lease `client` secrets at all, or rotate them on a schedule instead?

**Risks**

- **SDK behavior on revocation.** Server SDKs may keep retrying a revoked secret instead of re-reading their config, and may not react to the 4004 close code. Test the SDK versions you use.
- **Open connections outlive revocation** until fork change 4 lands. Until then, do not describe scenario 1 leases as enforced for streaming workloads.
- **Rotation stampede.** Workloads that all start together get the same `max_ttl` and rotate together. Jitter the switch time (for example 75% to 85% of `max_ttl`) to avoid bursts of `creds` reads and reconnects.
- **Upstream drift.** The fork touches both servers and three stores. Keep each change in its own commit so rebases stay mechanical.
- **Environment row growth.** Many concurrent leases per environment grow the JSON secrets column; quotas and longer TTLs are the control.
- **Admin token compromise.** Mitigated by per-scenario mounts and minimal permissions, but a scenario 2 token is powerful until the subset check lands.
