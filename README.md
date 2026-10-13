# exeris-caps-federated-login

Sign-in through an external identity provider as an Exeris capability. It provides `FederatedLoginFlow` (the OAuth 2.0 authorization-code flow with PKCE, state and nonce), `ExternalIdentityLink` (binding a provider identity to a local subject, with conflict detection) and `FederationProviderRegistry`, with adapters for Google and GitHub.

Status: proof of concept, built against `exeris-kernel` 0.13.0-SNAPSHOT. The API is not stable and no artefact has been published.

## Where it sits

- **Layer:** Layer 5 — Domain primitive (identity), in the Tier 2 capability map of [`high-level-architecture.md`](https://github.com/exeris-systems/exeris-docs/blob/main/high-level-architecture.md) §3.2.
- **Depends on:** `exeris-kernel-spi`, `exeris-sdk-composition-lifecycle` and `exeris-caps-audit-trail`.
- **Provides** (`@Provides`, all version 0.1.0): `FederatedLoginFlow`, `ExternalIdentityLink`, `FederationProviderRegistry`.
- **Requires** (`@Requires`, each declared `optional = true`): `eu.exeris.caps.federatedlogin.spi.OutboundCredentialStore`, `eu.exeris.kernel.spi.http.HttpClientEngine`, `eu.exeris.kernel.spi.security.identity.TokenValidator`, `eu.exeris.kernel.spi.persistence.TransactionalExecutor`, `eu.exeris.caps.audittrail.api.AuditLogSink`.
- **Wall (ADR-055):** `eu.exeris.caps.federatedlogin.api` is the cross-cap surface; `eu.exeris.caps.federatedlogin.internal` is private, and a sibling cap reaching into it fails the build. No Spring, servlet, Netty or reactive type may appear (ADR-006).

Behaviour worth knowing before composing it:

- The token exchange uses the kernel `HttpClientEngine`, and OIDC ID-token verification uses a kernel `TokenValidator`; both are optional requirements the composition supplies.
- Provider client credentials come from an interface this cap declares itself (`spi.OutboundCredentialStore`); an in-memory implementation ships in that package.
- Storage is in memory unless a kernel `TransactionalExecutor` is supplied, in which case a PostgreSQL repository is used. The DDL is `src/main/resources/schema/federated-login-schema.sql`; nothing applies it automatically.
- With PostgreSQL the PKCE verifier is sealed with AES-256-GCM, bound to the state, under a keyring every node must hold; construction fails without one. Consuming a state and opening it are one transaction, so a node that cannot open a state leaves it for one that can.
- `initiateLogin` returns a `browserBinding`. The SKU sets it on the user agent that started the flow (for example as a `__Host-` cookie with `Secure`, `HttpOnly` and `SameSite=Lax`) and passes it back in `CallbackExchangeCommand`; a callback from any other user agent is rejected, which is what stops login CSRF. Only its hash is stored.
- `redirectUri` must equal a configured URI for the provider and `targetPostLoginUrl` must be a relative path or on a configured origin; otherwise `initiateLogin` throws `InvalidRedirectException`. With no configuration every `initiateLogin` is rejected.
- Exception messages carry the HTTP status and the OAuth `error` code, never a provider response body.
- Account linking is the SKU's job. `ExternalIdentityLink.link` binds an identity to the subject it is given and does not authenticate that subject; call it only for a subject signed in during the current session, never from an email match.
- Provider credentials come from `spi.OutboundCredentialStore`, declared by this cap and not by a separate outbound-credentials capability.

## Configuration

The module reads its configuration from the environment when it is constructed (or from the `Map` given to the constructor that takes one). A missing or malformed required value throws `FederatedLoginConfigurationException`, which names the key and never its value.

| Key | Required | Meaning |
|---|---|---|
| `EXERIS_FEDERATED_LOGIN_STATE_KEYS` | with PostgreSQL | flow-state keyring, `<id>:<base64>[,<id>:<base64>…]` |
| `EXERIS_FEDERATED_LOGIN_STATE_KEYS_FILE` | with PostgreSQL | path to a file holding the same keyring, such as a mounted secret |
| `EXERIS_FEDERATED_LOGIN_REDIRECT_URIS` | to log in | `<provider>=<uri>[,<uri>…][;<provider>=…]`, exact callback URIs per provider |
| `EXERIS_FEDERATED_LOGIN_POST_LOGIN_ORIGINS` | no | `<origin>[,<origin>…]` allowed for an absolute `targetPostLoginUrl` |

Set exactly one of the two keyring keys. Each key must decode to 32 random bytes, for example from `openssl rand -base64 32`; the first entry seals new flow states and the later entries only open existing ones, so to rotate prepend a new entry and drop the old one once no flow of its age remains (a flow lives five minutes). Redirect URIs are `https`, or `http` on a loopback host, with no userinfo, query or fragment.

## Build & test

Requires JDK 25, Maven 3.9+ and a Docker daemon: `PostgresFederatedLoginLiveIT` starts PostgreSQL through Testcontainers and fails, rather than skips, when it cannot.

```bash
mvn compile -Dexeris.codegen.skip=true   # pass 1 — the processor writes capability metadata
mvn verify                               # pass 2 — generate cap-manifest.json, validate the graph, scan the Wall
```

Both passes are needed after a `clean`: `exeris:generate` runs before `compile`, and `compile` is when the processor writes the metadata it reads. `src/main/generated/java/cap-manifest.json` is committed, so a clean `git status` after `mvn verify` shows the manifest matches the declaration.

The upstreams are not on Maven Central. `exeris-sdk` v0.12.0 and `exeris-tooling` v0.9.0 are built from source at those tags, and `exeris-kernel` 0.13.0-SNAPSHOT is resolved from GitHub Packages, which needs a token with `read:packages`; the sibling `exeris-caps-audit-trail` (and its own dependency `exeris-caps-service-boundary-core`) are built from source first. [`.github/workflows/build.yml`](.github/workflows/build.yml) is the exact sequence, and [`.github/maven-settings.xml`](.github/maven-settings.xml) the repository configuration it uses.

## Documentation

- [`AGENTS.md`](AGENTS.md) — the repository's operating contract and invariants.
- [Capability Author Guide](https://github.com/exeris-systems/exeris-docs/blob/main/cap-author-guide.md) — how a cap declares `@CapabilityModule`, `@Provides`, `@Requires` and `@CapabilityLifecycle`.
- [Capability licence registry](https://github.com/exeris-systems/exeris-docs/blob/main/cap-license-registry.md) — the licence value of every cap.

Where they disagree, the ADRs below and the HLA outrank this README.

## Governing ADRs

- [ADR-006](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-006-spring-free-kernel-boundary.md) — Spring-free kernel boundary.
- [ADR-023](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-023-capability-licensing-taxonomy.md) — capability licensing taxonomy.
- [ADR-024](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-024-capability-composition-model.md) — capability composition model.
- [ADR-053](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-053-sku-composition-manifest-format.md) — composition manifest format.
- [ADR-055](https://github.com/exeris-systems/exeris-tooling/blob/main/docs/adr/ADR-055-cap-tier-wall-guard.md) — cap-tier Wall guard.
- [ADR-088](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-088-cryptographic-license-manifest-and-offline-verification.md) — signed licence manifest.
- [ADR-089](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-089-capability-entitlement-enforcement-and-runtime-contract.md) — capability entitlement enforcement.
- [ADR-099](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-099-compose-identity-as-a-tier-3-platform-sku.md) — the Identity SKU, which lists this cap.

Registry: [`adr-index.md`](https://github.com/exeris-systems/exeris-docs/blob/main/adr-index.md).

## License

Exeris Commercial License 1.1 — see [`LICENSE`](LICENSE). `exeris-caps-federated-login` is a `commercial` capability under [ADR-023](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-023-capability-licensing-taxonomy.md): the source is available to read, build, test and evaluate, and production use requires a commercial licence.

The cap enforces that at boot. It registers a kernel `EntitlementRequirement` whose capability id is `exeris-caps-federated-login`, and in a production-class environment the kernel's contract gate refuses to start unless a signed licence manifest lists that id among its entitlements ([ADR-088](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-088-cryptographic-license-manifest-and-offline-verification.md), [ADR-089](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-089-capability-entitlement-enforcement-and-runtime-contract.md)).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Report a suspected vulnerability as described in [`SECURITY.md`](SECURITY.md), never in a public issue.
