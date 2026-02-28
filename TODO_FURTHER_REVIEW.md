# TODO: Areas Requiring Further Review

This document lists specific areas of the ckb-discovery codebase that require further in-depth security review, testing, or remediation.

---

## Priority 1 — CRITICAL (Immediate Action Required)

### TODO-001: Audit and Remove All Hardcoded Credentials
- [ ] **`src/main.rs:22-23`** — Remove default MQTT user/pass (`ckb`/`ckbdiscovery`). Fail if env vars are missing.
- [ ] **`marci/src/main.rs:218-219`** — Same MQTT credential defaults.
- [ ] **`marci/src/main.rs:260`** — Default Redis URL `redis://:CkBdIsCoVeRy@redis`.
- [ ] **`marci/Dockerfile:14`** — Hardcoded `REDIS_URL` with password in Dockerfile.
- [ ] **`exposed/Dockerfile:13`** — Hardcoded `REDIS_URL` with password in Dockerfile.
- [ ] **`exposed/src/main.rs:417`** — CLI default `redis://:CkBdIsCoVeRy@127.0.0.1`.
- [ ] **`compose.yaml`** — Review all `${MQTT_PASS}`, `${REDIS_PASS}` usage; ensure `.env` is never committed.
- [ ] **Action**: Implement Docker Secrets or environment-only credential injection with no defaults.

### TODO-002: Fix Unsafe Mutable Static Data Race
- [ ] **`marci/src/main.rs:120-128`** — `ipinfo_cache()` uses `static mut` + `unsafe` — data race in async context.
- [ ] **`marci/src/main.rs:130-152`** — `ipinfo()` uses `static mut` + `unsafe` — data race in async context.
- [ ] **Action**: Replace with `tokio::sync::RwLock<HashMap<...>>` wrapped in `once_cell::sync::Lazy` or `std::sync::OnceLock<RwLock<...>>`.
- [ ] **Testing**: Add concurrent access test to verify thread safety.

### TODO-003: Fix All `.unwrap()` on Untrusted Network Data
- [ ] **`src/handler.rs:155`** — `addresses.get(0).unwrap()` — can panic on empty address list.
- [ ] **`src/handler.rs:155`** — `Multiaddr::try_from(...).unwrap()` — can panic on malformed multiaddr bytes.
- [ ] **`src/handler.rs:161`** — inner loop `Multiaddr::try_from(address.to_vec()).unwrap()`.
- [ ] **Action**: Replace with `match` / `if let` / `?` operator. Log and skip invalid addresses.
- [ ] **Testing**: Fuzz test with malformed DiscoveryMessage payloads.

### TODO-004: Replace `panic!()` in Async Tasks
- [ ] **`src/main.rs:138`** — `panic!("MQTT Context exited...")` in spawned task.
- [ ] **Action**: Return `Result<(), Error>` from the async block. Handle in `main()` with proper logging and restart logic.

### TODO-005: Validate Integer Overflow on Timeout Conversion
- [ ] **`marci/src/main.rs:337`** — `.try_into().unwrap()` on u64→usize conversion.
- [ ] **`marci/src/main.rs:366`** — Same pattern.
- [ ] **Action**: Clamp timeout values to `usize::MAX` or validate at startup. Use saturating conversion.

---

## Priority 2 — HIGH (Action Within Next Sprint)

### TODO-006: Input Validation for Redis Key Operations
- [ ] **`exposed/src/main.rs:81-86`** — Validate `peer_id` from query params before using in Redis keys.
- [ ] **`marci/src/main.rs:332-334`** — Validate `peer_id` from MQTT messages.
- [ ] **Action**: Implement a `validate_peer_id()` function. Peer IDs should be alphanumeric/base58, fixed length. Reject wildcards (`*`, `?`, `[`).
- [ ] **Testing**: Add unit tests for peer_id validation edge cases.

### TODO-007: Fix Index Out-of-Bounds in Key Parsing
- [ ] **`exposed/src/main.rs:258-262`** — `reachable_keys_to_peer_ids()` uses `[1]` index without bounds check.
- [ ] **Action**: Use `.get(1).unwrap_or(&"")` or filter out malformed keys.
- [ ] **Testing**: Unit test with keys that have fewer than 2 dot-separated segments.

### TODO-008: Review Bitflag Logic for Correctness
- [ ] **`src/handler.rs:90`** — `(client_flag | 0b1) == 0b1` — likely should be `(client_flag & 0b1) == 0b1`.
- [ ] **Action**: Cross-reference with CKB network protocol specification for correct flag interpretation.
- [ ] **Action**: Add named constants for flag bits (e.g., `const FLAG_FULL_NODE: u64 = 0b1;`).
- [ ] **Testing**: Unit test flag parsing with all known CKB flag values.

### TODO-009: Handle `unreachable!()` Paths
- [ ] **`src/main.rs:112`** — `CKBNetworkType::Dev` would trigger `unreachable!()`.
- [ ] **`exposed/src/main.rs:303-305`** — Same issue.
- [ ] **Action**: Replace with explicit error handling or add Dev handler.

### TODO-010: Add MQTT Reconnection Limits
- [ ] **`src/main.rs:129-135`** — Infinite reconnection loop with 1s delay.
- [ ] **`marci/src/main.rs:312-319`** — Same pattern.
- [ ] **Action**: Add max retry count (e.g., 100). Implement exponential backoff (1s, 2s, 4s, 8s, ..., max 60s). Exit with error after max retries.

### TODO-011: Review MQTT Keep-Alive Interval
- [ ] **`src/main.rs:35`** — `keep_alive_interval(Duration::from_millis(300))` — extremely aggressive.
- [ ] **`marci/src/main.rs:232`** — `keep_alive_interval(Duration::from_millis(100))` — even more aggressive.
- [ ] **Action**: Increase to 15-30 seconds. Document rationale if sub-second is truly needed.

### TODO-012: Replace Silent `CKBNetworkType` Fallback
- [ ] **`types/src/lib.rs:17`** — `_ => CKBNetworkType::Mirana` silently accepts any string.
- [ ] **Action**: Change `From<String>` to `TryFrom<String>` returning `Result`.
- [ ] **Note**: This affects callers in `marci/src/main.rs:434` and `exposed/src/main.rs:202`.

---

## Priority 3 — MEDIUM (Plan for Next Release)

### TODO-013: Replace Redis `KEYS` with `SCAN`
- [ ] **`exposed/src/main.rs:83,121,157,293-301,310-312`** — All `KEYS` commands.
- [ ] **`marci/src/main.rs:411`** — `KEYS` for reachable peers.
- [ ] **Action**: Use `SCAN` cursor-based iteration, or maintain secondary indexes (Redis SETs of known peer IDs per category).

### TODO-014: Add Decompression Rate Limiting
- [ ] **`src/compress.rs:10`** — 8MB max decompression per message.
- [ ] **Action**: Add per-connection memory tracking. Limit total decompressed bytes per time window.

### TODO-015: Fix Cache TOCTOU Race Condition
- [ ] **`exposed/src/main.rs:193-198`** — Check-then-lock pattern.
- [ ] **Action**: Acquire lock first, then check cache validity.

### TODO-016: Enable TLS for MQTT Connections
- [ ] **`compose.yaml`** — MQTT port 1883 is plaintext only.
- [ ] **Action**: Configure EMQX with TLS. Use `mqtts://` in all connection URLs.
- [ ] **Action**: Add certificate management documentation.

### TODO-017: Add Non-Root User to Dockerfiles
- [ ] **`Dockerfile`** — No USER directive.
- [ ] **`marci/Dockerfile`** — No USER directive.
- [ ] **`exposed/Dockerfile`** — No USER directive.
- [ ] **Action**: Add `RUN useradd -r appuser && USER appuser` before CMD.

### TODO-018: Remove Redundant `.clone().to_owned()` Pattern
- [ ] **`src/handler.rs:29,98,166`**
- [ ] **`src/main.rs:53`**
- [ ] **`marci/src/main.rs:244`**
- [ ] **Action**: Replace `.clone().to_owned()` with just `.clone()`.

---

## Priority 4 — LOW (Address Opportunistically)

### TODO-019: Replace `env::set_var` with Builder Pattern
- [ ] **`src/main.rs:18`** — Use `env_logger::Builder` instead.
- [ ] **`marci/src/main.rs:193`** — Same.

### TODO-020: Remove Unused Variables
- [ ] **`marci/src/main.rs:197-199`** — `_ckb_node_ex_timeout` parsed but never used.

### TODO-021: Make Buffer Sizes Configurable
- [ ] **`src/main.rs:64-65`** — 24MB send/receive buffers hardcoded.
- [ ] **Action**: Read from env vars with sane defaults.

### TODO-022: Add Version String Length Validation
- [ ] **`src/handler.rs:85-86`** — No max length on client_version.
- [ ] **Action**: Truncate or reject version strings > 256 bytes.

### TODO-023: Return `Option`/`Result` from Address Parsing Functions
- [ ] **`src/network.rs:65-86`** — `addr_to_node_meta()` defaults to `127.0.0.1`.
- [ ] **`src/network.rs:88-100`** — `addr_to_endpoint()` defaults to `127.0.0.1`.
- [ ] **Action**: Return `Option<NodeMetaInfo>` / `Option<EndpointInfo>`.

### TODO-024: Pre-compile Regex Patterns
- [ ] **`exposed/src/main.rs:92,129,337`** — `Regex::new()` called per request.
- [ ] **Action**: Use `lazy_static!` or `once_cell::sync::Lazy` to compile regex once.

---

## Priority 5 — Enhancements (Best Practice)

### TODO-025: Add Observability and Metrics
- [ ] Integrate Prometheus metrics (connection count, message rates, error rates).
- [ ] Add structured logging (tracing crate).

### TODO-026: Add Integration Tests
- [ ] No test infrastructure exists in the repository.
- [ ] Add unit tests for `network.rs` address parsing functions.
- [ ] Add unit tests for `compress.rs` compress/decompress round-trip.
- [ ] Add integration tests for MQTT message handling.

### TODO-027: Add CI/CD Pipeline
- [ ] No GitHub Actions workflows exist.
- [ ] Add `cargo clippy`, `cargo test`, `cargo audit` to CI.
- [ ] Add Dependabot for dependency updates.

### TODO-028: Dependency Security Audit
- [ ] Run `cargo audit` on all workspace members.
- [ ] Review `paho-mqtt 0.13` for known vulnerabilities.
- [ ] Review `ipinfo 2.1.0` for known vulnerabilities.
- [ ] Review all transitive dependencies via `Cargo.lock`.

---

## Summary

| Priority | Count | Description |
|----------|-------|-------------|
| P1 (Critical) | 5 | Security vulnerabilities requiring immediate fix |
| P2 (High) | 7 | Bugs and security issues for next sprint |
| P3 (Medium) | 6 | Architecture improvements for next release |
| P4 (Low) | 6 | Code quality improvements |
| P5 (Enhancement) | 4 | Best practice additions |
| **Total** | **28** | |
