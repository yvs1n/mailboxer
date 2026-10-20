# E2E Test Infra: Mailboxer Core Connection & Verification Engine

## Test Philosophy
- **Opaque-box, requirement-driven**: Test suite is derived strictly from `ORIGINAL_REQUEST.md` and user-facing specifications, with zero dependence on implementation internals.
- **100% Offline Hermetic Isolation**: Automated tests (`npm test`) must run cleanly without network access, third-party test runners, or real credentials.
- **Methodology**: Systematic 4-tier approach (Category-Partition, Boundary Value Analysis, Pairwise Combinatorial Testing, Real-World Scenarios) + Tier 5 Adversarial Coverage Hardening.

## Feature Inventory & Test Coverage Goals
| # | Feature | Requirement Source | Tier 1 (Coverage) | Tier 2 (Boundaries) | Tier 3 (Pairwise) | Tier 4 (Real-World) |
|---|---------|-------------------|:-----------------:|:-------------------:|:-----------------:|:-------------------:|
| F1 | Apple Mail Preset | ORIGINAL_REQUEST §R1 | ≥5 cases | ≥5 cases | ✓ | ✓ |
| F2 | Gmail Preset | ORIGINAL_REQUEST §R1 | ≥5 cases | ≥5 cases | ✓ | ✓ |
| F3 | Outlook Preset | ORIGINAL_REQUEST §R1 | ≥5 cases | ≥5 cases | ✓ | ✓ |
| F4 | Strict Schema Validation | ORIGINAL_REQUEST §R1 | ≥5 cases | ≥5 cases | ✓ | ✓ |
| F5 | Environment Loader & Masking | ORIGINAL_REQUEST §R1 | ≥5 cases | ≥5 cases | ✓ | ✓ |
| F6 | Documented `.env.example` | ORIGINAL_REQUEST §R1 | ≥5 cases | ≥5 cases | ✓ | ✓ |
| F7 | Pluggable Socket Transport | ORIGINAL_REQUEST §R2 | ≥5 cases | ≥5 cases | ✓ | ✓ |
| F8 | TLS Handshake & Cipher Audit | ORIGINAL_REQUEST §R2 | ≥5 cases | ≥5 cases | ✓ | ✓ |
| F9 | IMAP State Machine & INBOX | ORIGINAL_REQUEST §R2 | ≥5 cases | ≥5 cases | ✓ | ✓ |
| F10 | Diagnostic Error Taxonomy | ORIGINAL_REQUEST §R2 | ≥5 cases | ≥5 cases | ✓ | ✓ |
| F11 | Standalone Diagnostic CLI | ORIGINAL_REQUEST §R3 | ≥5 cases | ≥5 cases | ✓ | ✓ |
| F12 | Graceful Missing Credential Exit | ORIGINAL_REQUEST §R3 | ≥5 cases | ≥5 cases | ✓ | ✓ |
| F13 | Structured Status Reporting | ORIGINAL_REQUEST §R3 | ≥5 cases | ≥5 cases | ✓ | ✓ |

## Test Architecture
- **Runner**: Node.js 22 native test runner via `node --test --test-reporter=spec test/**/*.test.js`.
- **Pass/Fail Semantics**: Process exits with code 0 on all tests passing, non-zero on failure.
- **Mock Transport**: In-memory duplex socket stream simulator (`test/helpers/mock-socket.js`) simulating wire-level TLS and IMAP dialogue without TCP binding or external network access.
- **Directory Layout**:
  - `test/helpers/` — Mock transports, stream helpers, test fixtures.
  - `test/unit/` — Tier 1 & Tier 2 unit tests (presets, schema, env, error classifier).
  - `test/integration/` — Tier 2 & Tier 3 integration tests (connection lifecycle, error paths, CLI runner).
  - `test/e2e/` — Tier 4 real-world multi-account triage scenarios.

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Complexity |
|---|----------|--------------------|------------|
| 1 | Multi-Account Cold Boot & Missing Credentials | F5, F6, F11, F12, F13 | Medium |
| 2 | Unified Tri-Provider Triage Connection Cycle | F1, F2, F3, F7, F8, F9, F13 | High |
| 3 | Provider App-Password Migration & Failure Recovery | F4, F9, F10, F13 | High |
| 4 | Network Outage & Socket Drop Resiliency | F7, F8, F9, F10 | Medium |
| 5 | University Outlook Basic Auth Deprecation Flow | F3, F9, F10, F12, F13 | Medium |

## Coverage Thresholds
- Tier 1 (Feature Coverage): ≥65 tests (≥5 tests × 13 features)
- Tier 2 (Boundary & Corner Cases): ≥65 tests
- Tier 3 (Cross-Feature Combinations): ≥13 tests
- Tier 4 (Real-World Scenarios): ≥5 tests
- Total Minimum Target: ≥148 tests
