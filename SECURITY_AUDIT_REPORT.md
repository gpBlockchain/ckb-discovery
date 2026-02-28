# Security Audit Report: ckb-discovery

**Date**: 2026-02-28  
**Auditor**: Automated Security Review  
**Scope**: Full codebase including `src/`, `types/`, `marci/`, `exposed/`, Docker & compose configurations  
**Methodology**: Manual code review + Automated scanning (CodeQL, code_review)

---

## Executive Summary

The ckb-discovery project consists of three main modules:
1. **Discovery** (`src/`) — A P2P dialer/probe that connects to CKB network nodes via the tentacle framework, discovers peers, and publishes results to MQTT.
2. **Marci** (`marci/`) — A message broker that consumes MQTT events (peer online/reachable/unknown), stores state in Redis, and schedules re-dials.
3. **Exposed** (`exposed/`) — An HTTP API service (actix-web) that queries Redis and serves peer data to frontends.

The audit identified **5 CRITICAL**, **7 HIGH**, **6 MEDIUM**, **6 LOW**, and **3 INFO** level findings across security, reliability, and code quality dimensions.

---

## Findings

### CRITICAL Severity

#### C-01: Hardcoded Credentials in Docker & Configuration Files

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **Location** | `marci/Dockerfile:14`, `exposed/Dockerfile:13`, `compose.yaml:29,41-44`, `.env.example:1-4`, `exposed/src/main.rs:417`, `marci/src/main.rs:260` |
| **CWE** | CWE-798 (Use of Hard-coded Credentials) |

**Description**: Default Redis password `CkBdIsCoVeRy` is hardcoded in both `marci/Dockerfile` and `exposed/Dockerfile` as environment variable defaults. MQTT credentials (`ckb`/`ckbdiscovery`) are hardcoded as defaults in `src/main.rs:22-23` and `marci/src/main.rs:218-219`. The `exposed/src/main.rs:417` has `redis://:CkBdIsCoVeRy@127.0.0.1` as a CLI default.

**Impact**: Anyone with code access can extract production credentials. If Docker images are published, credentials are embedded in the image layers.

**Evidence**:
```rust
// src/main.rs:22-23
let mqtt_user = env::var("MQTT_USER").unwrap_or("ckb".to_string());
let mqtt_pass = env::var("MQTT_PASS").unwrap_or("ckbdiscovery".to_string());
```
```dockerfile
# marci/Dockerfile:14
ENV REDIS_URL="redis://:CkBdIsCoVeRy@redis"
```

**Recommendation**: Remove all hardcoded credentials. Use Docker Secrets, Kubernetes Secrets, or a vault. Make environment variables required (fail fast if absent) instead of providing insecure defaults.

---

#### C-02: Unsafe Mutable Static Variables (Data Race)

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **Location** | `marci/src/main.rs:120-152` |
| **CWE** | CWE-362 (Concurrent Execution Using Shared Resource with Improper Synchronization) |

**Description**: Two `static mut` + `OnceLock` patterns are used to create mutable global singletons for `IPINFO_CACHE` (HashMap) and `IPINFO` (IpInfo client). The code uses `unsafe` blocks with the comment "Safety: only one thread can access here" — but this is running in a tokio async runtime with multiple tasks that can preempt each other.

**Impact**: Data races on `HashMap` and `IpInfo` client. Concurrent reads/writes to the cache can cause undefined behavior, memory corruption, or panics.

**Evidence**:
```rust
fn ipinfo_cache() -> &'static mut HashMap<String, IpDetails> {
    static mut IPINFO_CACHE: OnceLock<HashMap<String, IpDetails>> = OnceLock::new();
    unsafe {
        IPINFO_CACHE.get_or_init(Default::default);
        IPINFO_CACHE.get_mut().unwrap()
    }
}
```

**Recommendation**: Replace with `once_cell::sync::Lazy<tokio::sync::RwLock<HashMap<...>>>` or `tokio::sync::OnceCell<RwLock<...>>`. Remove all `unsafe` blocks. Do NOT use `std::sync::OnceLock` with mutable access as it recreates the same unsafety.

---

#### C-03: Multiple Unwrap Calls on Untrusted Network Data

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **Location** | `src/handler.rs:155-161`, `src/network.rs:43,60` |
| **CWE** | CWE-252 (Unchecked Return Value), CWE-400 (Uncontrolled Resource Consumption) |

**Description**: In `received_discovery()`, multiaddress bytes received from remote peers are parsed with `.unwrap()` calls:
```rust
let mut meta = addr_to_node_meta(
    &Multiaddr::try_from(addresses.get(0).unwrap().to_vec()).unwrap(),
    self.network_type,
);
```
If a malicious peer sends a malformed `DiscoveryMessage` with invalid addresses, the `.unwrap()` calls will panic and crash the handler.

Additionally, `network.rs:43` calls `.parse().unwrap()` on bootnode strings (lower risk since these are hardcoded), and `network.rs:59-60` has `.unwrap()` on `multiaddr_to_socketaddr` fallback.

**Impact**: Remote Denial of Service — any connected peer can crash the discovery service by sending malformed discovery messages.

**Recommendation**: Replace `.unwrap()` with proper error handling. Skip invalid addresses with `continue` in loops. Log the error and move on.

---

#### C-04: Panic in Production Async Tasks

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **Location** | `src/main.rs:138` |
| **CWE** | CWE-755 (Improper Handling of Exceptional Conditions) |

**Description**: The MQTT consumer task ends with `panic!("MQTT Context exited, Maybe service not ready...");` after the stream loop exits. In a tokio runtime, a panic in a spawned task is caught by the runtime and the task silently dies. The `mqtt_tx.await?` will return an error, but the error message is not actionable.

**Impact**: Silent service death. The MQTT consumer fails, but the P2P service continues running without processing any MQTT commands, making the system appear alive but non-functional.

**Recommendation**: Use proper error propagation instead of panics. Return `Result` from the async block and handle it in the main function with clear logging and potential restart logic.

---

#### C-05: Integer Overflow on Timeout Conversion

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **Location** | `marci/src/main.rs:337,366` |
| **CWE** | CWE-190 (Integer Overflow or Wraparound) |

**Description**: The `ckb_node_default_timeout` is parsed as `u64` but then converted to `usize` via `.try_into().unwrap()`. On 32-bit architectures, if the timeout exceeds `u32::MAX` (4,294,967,295 seconds ≈ 136 years), this will panic. While the default value (5184000 = 60 days) is safe, user-configured values could trigger this.

```rust
con.expire::<String, usize>(online_key.clone(), ckb_node_default_timeout.try_into().unwrap()).await?;
```

**Impact**: Process crash if configured with large timeout values on 32-bit systems.

**Recommendation**: Validate timeout bounds at startup. Cap at a reasonable maximum (e.g., 1 year). Use `i64` or `usize` consistently.

---

### HIGH Severity

#### H-01: Redis Key Injection via Unsanitized Peer ID

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Location** | `exposed/src/main.rs:81-86`, `marci/src/main.rs:332-334,360-363,382-384` |
| **CWE** | CWE-943 (Improper Neutralization of Special Elements in Data Query Logic) |

**Description**: Peer IDs from external sources (MQTT messages, HTTP query parameters) are used directly in Redis key construction without any validation:
```rust
let peer_id = query_params.peer_id.clone();
client.keys(format!("peer.online.{}", peer_id)).await
```
A malicious peer_id like `*` could match all keys with `KEYS peer.online.*`. In the exposed API, the `peer_id` query parameter goes directly into `KEYS` commands.

**Impact**: Information disclosure — attacker can enumerate all peer data. The `KEYS` command with wildcards is also a performance concern (O(N) scan).

**Recommendation**: Validate peer_id format (alphanumeric only, fixed length). Use `GET` instead of `KEYS` where possible.

---

#### H-02: Index Out-of-Bounds Panic in Key Parsing

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Location** | `exposed/src/main.rs:258-262` |
| **CWE** | CWE-129 (Improper Validation of Array Index) |

**Description**: The `reachable_keys_to_peer_ids` function assumes Redis keys have a specific format and uses direct array indexing:
```rust
fn reachable_keys_to_peer_ids(keys: &[String]) -> Vec<&str> {
    keys.iter()
        .map(|key| key.rsplit('.').collect::<Vec<_>>()[1])
        .collect::<Vec<_>>()
}
```
If any key doesn't have at least 2 dot-separated segments, this will panic with index out of bounds.

**Impact**: Service crash from unexpected Redis key format.

**Recommendation**: Use `.get(1).unwrap_or(&"")` or validate key format before parsing.

---

#### H-03: Unreachable Macro on Exhaustive Enum Match

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Location** | `src/main.rs:112`, `exposed/src/main.rs:303-305` |
| **CWE** | CWE-394 (Unexpected Status Code or Return Value) |

**Description**: Multiple locations use `_ => unreachable!()` on the `CKBNetworkType` enum. If a new variant (e.g., `Dev`) reaches these code paths, the program will panic.

**Impact**: Runtime panic if the Dev network type is used, or if new network types are added.

**Recommendation**: Handle all enum variants explicitly, or use a proper fallback with error logging.

---

#### H-04: Infinite Reconnection Loop Without Backoff Limit

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Location** | `src/main.rs:129-135`, `marci/src/main.rs:312-319` |
| **CWE** | CWE-835 (Loop with Unreachable Exit Condition) |

**Description**: MQTT reconnection loops retry forever with only 1-second delay:
```rust
while let Err(err) = mqtt_client.reconnect().await {
    rconn_attempt += 1;
    info!("Error reconnecting #{}: {}", rconn_attempt, err);
    tokio::time::sleep(Duration::from_secs(1)).await;
}
```
No maximum retry limit, no exponential backoff, no alerting mechanism.

**Impact**: If the MQTT broker is permanently unreachable, the service spins forever, consuming CPU and log space.

**Recommendation**: Add maximum retry count with exponential backoff. Alert/exit after exceeding threshold.

---

#### H-05: Bitflag Logic Error in Full Node Detection

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Location** | `src/handler.rs:90` |
| **CWE** | CWE-480 (Use of Incorrect Operator) |

**Description**: The node capability check uses confusing bitwise logic:
```rust
let full = (client_flag | 0b1) == 0b1 || (client_flag & 0b11110) == 0b11110;
```
The expression `(client_flag | 0b1) == 0b1` is only true when `client_flag` is `0` or `1`. This means: "is full if the flag value is 0 or 1, OR if bits 1-4 are all set." The first condition likely has a bug — it should probably be `(client_flag & 0b1) == 0b1` (bitwise AND to test if bit 0 is set).

**Impact**: Incorrect peer capability classification. Non-full nodes may be marked as full, or full nodes may be missed.

**Recommendation**: Review the CKB protocol spec for correct flag interpretation. Use named constants for flag bits.

---

#### H-06: Unvalidated `CKBNetworkType` Silent Fallback

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Location** | `types/src/lib.rs:13-18` |
| **CWE** | CWE-394 (Unexpected Status Code or Return Value) |

**Description**: The `From<String>` impl for `CKBNetworkType` silently defaults to `Mirana` for any unrecognized network string:
```rust
_ => CKBNetworkType::Mirana,
```

**Impact**: Configuration typos (e.g., `network=mainnet` instead of `main`) silently connect to the wrong network.

**Recommendation**: Use `TryFrom<String>` instead, returning an error for unrecognized values.

---

#### H-07: Very Short MQTT Keep-Alive Interval

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Location** | `src/main.rs:35`, `marci/src/main.rs:232` |
| **CWE** | CWE-400 (Uncontrolled Resource Consumption) |

**Description**: MQTT keep-alive is set to 100-300ms:
```rust
.keep_alive_interval(Duration::from_millis(300))  // ckb-discovery
.keep_alive_interval(Duration::from_millis(100))  // marci
```
Standard MQTT keep-alive is typically 30-60 seconds. Such aggressive intervals will cause excessive network traffic and potentially trigger rate limits or be interpreted as a DDoS.

**Impact**: Unnecessary network overhead. May cause spurious disconnections under normal network latency.

**Recommendation**: Increase to at least 10-30 seconds.

---

### MEDIUM Severity

#### M-01: Decompression Bomb Potential

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Location** | `src/compress.rs:10,70-78` |
| **CWE** | CWE-409 (Improper Handling of Highly Compressed Data) |

**Description**: The maximum uncompressed length is 8MB (`1 << 23`). While this limit exists, a small compressed message could expand to 8MB, consuming significant memory per connection. With many concurrent connections, this becomes a memory exhaustion vector.

**Impact**: Memory exhaustion attack via many compressed messages at the decompression limit.

**Recommendation**: Add per-connection rate limiting and total memory budget tracking.

---

#### M-02: No Rate Limiting on Discovery Requests

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Location** | `src/handler.rs:70-77` |
| **CWE** | CWE-770 (Allocation of Resources Without Limits or Throttling) |

**Description**: Every new connection immediately triggers a `GetNodes` request with `max_nodes: 1000`. There's no rate limiting on how frequently connections can be made or discovery requests sent.

**Impact**: A flood of connections can overwhelm the service with discovery processing.

**Recommendation**: Implement connection rate limiting and throttle discovery requests.

---

#### M-03: Redis `KEYS` Command Used in Production

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Location** | `exposed/src/main.rs:83-86,121-123,157-160,293-301,310-312`, `marci/src/main.rs:411` |
| **CWE** | CWE-400 (Uncontrolled Resource Consumption) |

**Description**: The Redis `KEYS` command is used extensively. Redis documentation explicitly warns against using `KEYS` in production as it performs a full keyspace scan (O(N) complexity) and blocks the Redis server during execution.

**Impact**: Performance degradation under high key counts. Can block Redis for other clients.

**Recommendation**: Use `SCAN` for iteration, or maintain indexed sets (e.g., a Redis SET of all online peer IDs).

---

#### M-04: TOCTOU Race in Cache Logic

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Location** | `exposed/src/main.rs:193-198` |
| **CWE** | CWE-367 (Time-of-Check Time-of-Use) |

**Description**: The peer_handler checks if cache is empty or stale, then separately locks and updates. Between the check and the update, another request could also see stale data and trigger a redundant refresh.

**Impact**: Multiple concurrent Redis queries when a single one would suffice; possible data inconsistency during refresh.

**Recommendation**: Use a single lock for both check and update, or use an atomic cache pattern.

---

#### M-05: Redundant Clone Pattern

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Location** | `src/handler.rs:29,98,166`, `src/main.rs:53`, `marci/src/main.rs:244` |
| **CWE** | N/A (Code Quality) |

**Description**: Repeated pattern of `.clone().to_owned()` which is redundant. `.clone()` already produces an owned value.

**Impact**: Unnecessary memory allocation and CPU usage.

**Recommendation**: Use `.clone()` only.

---

#### M-06: No TLS for MQTT Connection

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Location** | `src/main.rs:21`, `marci/src/main.rs:217`, `compose.yaml:23` |
| **CWE** | CWE-319 (Cleartext Transmission of Sensitive Information) |

**Description**: MQTT connections use plaintext `mqtt://` protocol. MQTT credentials and all peer data are transmitted in cleartext.

**Impact**: Network eavesdropping can capture MQTT credentials and peer information.

**Recommendation**: Use `mqtts://` (MQTT over TLS) in production deployments.

---

### LOW Severity

#### L-01: Default Loopback Address as Fallback

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Location** | `src/network.rs:68,90` |
| **CWE** | CWE-1188 (Initialization with Hard-Coded Network Resource Configuration) |

**Description**: Functions `addr_to_node_meta` and `addr_to_endpoint` default to `127.0.0.1` if no IP is found in the multiaddr. This masks parsing failures.

**Recommendation**: Return `Option<>` or `Result<>` instead of using a fallback.

---

#### L-02: Unused Variables and Dead Code

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Location** | `marci/src/main.rs:197-199` |

**Description**: `_ckb_node_ex_timeout` is parsed from environment but never used.

**Recommendation**: Remove if unused, or document intended use.

---

#### L-03: Hardcoded Buffer Sizes

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Location** | `src/main.rs:64-65` |

**Description**: Send/receive buffers fixed at 24MB each. Not configurable.

**Recommendation**: Make configurable via environment variables.

---

#### L-04: No Input Length Validation on Identify Payload

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Location** | `src/handler.rs:85-86` |

**Description**: Client version string extracted from identify payload without length validation.

**Recommendation**: Add maximum length check for version strings.

---

#### L-05: `env::set_var` is Unsafe in Multi-threaded Context

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Location** | `src/main.rs:18`, `marci/src/main.rs:193` |
| **CWE** | CWE-362 |

**Description**: `env::set_var("RUST_LOG", "info")` is called at startup. In recent Rust editions, this is marked as unsafe because it modifies the process environment which is shared state. While it's called before `env_logger::init()` and before spawning threads, it's still a code smell.

**Recommendation**: Use `env_logger::Builder::new().filter_level(log::LevelFilter::Info).init()` instead.

---

#### L-06: Docker Image Runs as Root

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Location** | `Dockerfile`, `marci/Dockerfile`, `exposed/Dockerfile` |
| **CWE** | CWE-250 (Execution with Unnecessary Privileges) |

**Description**: All three Dockerfiles run the application as root (no `USER` directive).

**Recommendation**: Add a non-root user and `USER` directive in Dockerfiles.

---

### INFO / Code Quality

#### I-01: Excessive Cloning of Data Structures
- **Location**: `src/handler.rs:149,166,173`
- Use `Arc<T>` for shared data across async tasks instead of cloning.

#### I-02: Inconsistent Error Handling Patterns
- Some errors use `unwrap_or_default()`, others use `?`, others use `expect()`. Standardize.

#### I-03: No Observability Metrics
- No Prometheus/metrics integration. Add health check metrics, connection counts, message rates, etc.

---

## Risk Matrix

| Severity | Count | Risk Level |
|----------|-------|------------|
| CRITICAL | 5 | Immediate action required |
| HIGH | 7 | Action within 1 sprint |
| MEDIUM | 6 | Plan for next release |
| LOW | 6 | Address opportunistically |
| INFO | 3 | Best practice improvements |

## Conclusion

The codebase has several critical security issues that should be addressed before production deployment:

1. **Hardcoded credentials** in Docker images and code defaults
2. **Unsafe mutable statics** causing potential data races in async context
3. **Unvalidated network input** leading to panic/DoS vulnerabilities
4. **Missing input validation** on peer IDs enabling Redis key injection
5. **Bitflag logic error** in peer capability detection

The most urgent fixes are C-01 (credentials), C-02 (unsafe data race), and C-03 (DoS via malformed messages).
