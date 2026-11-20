# norma fork (v0.4.4)

This directory is a local fork of `github.com/Autumn-27/norma` v0.4.4. The main
module points here through:

```go
replace github.com/Autumn-27/norma => ./third_party/norma
```

## Why

ARTEX Watchdog termination needs to ask a **running** worker to enter the SDK's
existing `Settlement` wrap-up phase instead of cancelling its context. Upstream
v0.4.4 and `main` do not expose that entry point yet, so the fork carries the
minimal API:

- `agentcore.Options.SettlementRequest <-chan string`
- `harness.QueryInput.SettlementRequest <-chan string`
- `harness.ReasonWatchdog`
- `loop.checkSettlementRequest` at model-turn boundaries; the request uses the
  caller's existing `Settlement` prompt/disabled tools/turn budget and the run
  finishes with `ReasonWatchdog`.

No other upstream behavior is changed on purpose.

## Upgrading

1. Copy the new upstream release over this directory (keep this file).
2. Re-apply the changes above (search for `SettlementRequest` and `ReasonWatchdog`).
3. Run the ARTEX-consumed fork gate and the backend tests:
   `go test ./agentcore ./harness ./llm ./tool`.
4. Run `go test ./...` as a full fork audit. The `noa` and `noaadapter` packages
   are independent context-compression code with their own platform-sensitive
   baseline tests; failures there do not block the ARTEX settlement API gate and
   must be triaged separately.
5. Once an upstream release contains the API, delete the fork, the `replace`
   directive, and this file; bump `require` normally.

### Baseline audit

The required ARTEX release gate includes the complete fork test suite:
`go test ./...`. The seven previously failing tests were compared against
upstream v0.4.4 on Windows `windows/amd64` with Go 1.26.3, then repaired in
this fork. The upstream comparison remains diagnostic only; it is not a reason
to permit local failures. Any failure in `go test ./...` blocks the fork gate.
