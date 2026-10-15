---
title: "Federated login capability roadmap"
type: roadmap
visibility: public
owning-repo: exeris-caps-federated-login
status: active
last-verified: 2026-10-15
---

# Roadmap

This file lists what the proof of concept does not cover. Read it together with the code: each item names the path it concerns, and the change that closes an item removes it from this file. The README states what the capability does today; this file states what it does not.

Milestones are versions, not dates.

A gap that must close before the first `0.1.0` release is listed under "Before 0.1.0" and has an issue in the `0.1.0` milestone, so the milestone shows what blocks the release. Everything else is under "Later".

## Before 0.1.0

### Provider response content in JSON parse errors

Tracking issue: [#12](https://github.com/exeris-systems/exeris-caps-federated-login/issues/12).

The README states that exception messages never carry a provider response body. `JsonReader.parseObject` and `JsonReader.parseArray` break that statement: on a value of the wrong type they put the parsed response into the exception message, and the provider adapters let that `IllegalArgumentException` escape `processExchange` unwrapped. A token, profile or email response that is not the expected JSON shape therefore reaches logs and error responses. The code is `JsonReader` in the `internal.http` package and its calls in `GoogleFederationProvider` and `GitHubFederationProvider` in `internal.provider`. The item closes when a malformed or wrongly typed body yields a `ProviderCommunicationException` that names the HTTP status only, with a test per response that asserts a marker string in the body is absent from the message.

## Later

### Composition does not supply the optional requirements

The module declares `TransactionalExecutor`, `HttpClientEngine`, `TokenValidator`, `OutboundCredentialStore` and `AuditLogSink` as optional requirements, but receives them only through constructor arguments. `initialize()` in `FederatedLoginModule` does nothing, and the public no-argument constructor that reflective instantiation uses wires in-memory storage and no HTTP client or token validator. A composition that instantiates the module reflectively therefore gets a module that cannot complete a Google or GitHub exchange and keeps flow state and identity links in process memory, lost on restart. A SKU that builds the module itself, with the constructor that takes a `TransactionalExecutor`, is unaffected.

`TransactionalExecutor` stays `optional = true` because the capability graph reports a `@Requires` on a kernel SPI type as unsatisfied (`EXT-PLUG-2201`); that is tracked in [exeris-tooling#409](https://github.com/exeris-systems/exeris-tooling/issues/409). The kernel `development/0.13.0` branch publishes `KernelProviders.TRANSACTIONAL_EXECUTOR` and `HttpKernelProviders.HTTP_CLIENT_ENGINE`, which `initialize()` can read. The item waits on the tooling change before the requirement can become mandatory, and on a published kernel 0.13 for the providers to resolve outside a snapshot build.

### Missing collaborators fail late

A callback that reaches a provider adapter without an `HttpClientEngine`, or the Google adapter without a `TokenValidator`, throws `IllegalStateException` inside `processExchange`, after the flow state has been consumed. The user must start the login again, and the misconfiguration shows only when the first user logs in. A check in `ready()` of `FederatedLoginModule` would stop the module before it accepts traffic. The item depends on the previous one, because the module knows what it was given only once it takes its requirements in `initialize()`.

### A known state value burns a pending flow

`processCallback` consumes the flow state before it compares the browser binding, the provider and the redirect URI (`DefaultFederatedLoginFlow` in `internal.flow`). Anyone who learns a pending `state` value can submit a callback with a wrong binding, which deletes the state and forces the user to log in again. No login is granted, so this is an availability cost, and the test suite pins the current behaviour. Moving the binding comparison into the consuming statement (`DELETE ... WHERE browser_binding_hash = $2`) keeps the single-use guarantee and leaves the row for the real user agent, but changes the `FlowStateRepository.consume` contract in `internal/repository`. It waits on a decision between that contract change and the current behaviour.

### Expired flow states are never pruned

`FlowStateRepository.pruneExpired` exists in both repositories, and nothing calls it. A flow that is started and never completed leaves a row until its state is presented, and `initiateLogin` needs no authentication, so the table (or the in-memory map) grows without bound. The code is `internal/repository/PostgresFlowStateRepository.java` and `internal/repository/InMemoryFlowStateRepository.java`. A scheduled prune needs a lifecycle hook and a schedule; the module lifecycle has the place for it, and the interval is a design choice.

### No limit on login initiation

Neither `initiateLogin` nor `processCallback` limits how often a caller may start a flow or submit a callback, and the capability keeps no per-caller state to do it with. Together with flow states that are never pruned this makes initiation a cheap way to fill storage. Whether a limit belongs in this capability or in the edge that fronts the SKU is undecided.

### The schema is applied by hand

`src/main/resources/schema/federated-login-schema.sql` creates tables only when they are absent, and nothing applies it. A table created by a build that predates a column keeps its old shape: `browser_binding_hash` is the current example. There is no migration path and no check at start-up that the tables match what the repositories expect. The item waits on a migration convention for capabilities that own tables.

### Only an in-memory credential store ships

`OutboundCredentialStore` has one implementation, `spi/InMemoryOutboundCredentialStore.java`, which holds client secrets in process memory and is filled by code. ADR-099 names `outbound-credentials` as the source of OAuth client secrets, and this capability instead declares its own SPI. The item waits on an amendment to ADR-099 in `exeris-docs`, or on an `outbound-credentials` capability that implements this SPI.

### Trust in the ID-token signature lies entirely with the injected validator

`GoogleFederationProvider` checks issuer, audience, authorised party, nonce and expiry on the claims a kernel `TokenValidator` returns, and relies on that validator for the signature check against Google's keys. Nothing in the capability can tell whether the injected validator trusts Google's key set, or some other issuer's. The issuer check limits the damage, but a validator configured with the wrong key source would fail every login rather than fail visibly at start-up. The item waits on a kernel-side way to ask a validator which issuers it trusts.

### The provider set is fixed

The public constructors of `FederatedLoginModule` always build a registry from the Google and GitHub adapters. `FederationProviderRegistry` is extensible, but only the package-private wiring constructor accepts another registry, so a SKU cannot add a provider without a change in this repository. Provider hosts and endpoints are also constants in the adapters. A generic OIDC adapter driven by discovery, and a public way to supply providers, are not designed yet.
