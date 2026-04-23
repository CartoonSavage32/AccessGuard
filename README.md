# AccessGuard

Detect unintended data access and privilege escalation in backend systems.

## What it does
AccessGuard scans Python backend code, identifies HTTP route handlers, and traces what each route can call across helper functions and service methods. It reports risky paths where a route reaches sensitive operations.

## Why it matters
Security bugs are often indirect. A route that looks simple can still trigger admin actions or sensitive reads through multi-step call chains. AccessGuard makes those hidden paths visible during development and review.

## Example
```bash
accessguard scan examples/sample_app
```

```text
=== AccessGuard Report ===

Summary:
  Routes scanned: 6
  Risks found: 4 HIGH / 0 MEDIUM / 0 LOW

Risks:
  [HIGH] GET /users (score: 6)
    Potential privilege escalation: route '/users' accesses sensitive operation 'billing_service.get_data'. Verify this is intended.
  [HIGH] POST /contact (score: 6)
    Potential privilege escalation: route '/contact' accesses sensitive operation 'admin_service.reset_system'. Verify this is intended.
```

## Installation
- `pip install -e .`
- `poetry install`

## Usage
```bash
accessguard scan .
```

Flags:
- `--json`
- `--quiet`
- `--fail-on-high`

## How it works
AccessGuard parses source files with Python AST, extracts routes and function calls, then builds a call graph. It follows multi-hop traversal from each route to sensitive nodes and applies deterministic risk rules.

## What it detects
- domain mismatch
- privilege escalation
- multi-hop access

## Limitations
- Static analysis only; no runtime state or data-flow guarantees
- Name-based resolution can miss dynamic imports and metaprogramming
- Heuristic keyword matching can produce false positives or false negatives
- Designed for Python backend route patterns

## Roadmap
- Improve symbol and import resolution
- Expand test coverage and CI hardening
- Publish stable packaged releases

