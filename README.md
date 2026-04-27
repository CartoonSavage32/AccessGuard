# AccessGuard

**Detect unintended data access and privilege escalation in Python backends — before they reach production.**

![Python](https://img.shields.io/badge/python-3.13%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## The Problem

Security bugs in backends are often *indirect*. A route that looks harmless in isolation can silently reach admin logic, billing services, or token decryption through a chain of internal calls — none of which is obvious from a code review.

```
GET /users
  → fetch_user_data()
    → billing_service.get_data()   ← Should /users really touch billing?
```

AccessGuard traces these hidden execution paths and surfaces them early, during development.

---

## Quick Start

```bash
git clone https://github.com/CartoonSavage32/AccessGuard
cd AccessGuard
pip install -e .
accessguard scan .
```

---

## Example Output

```bash
accessguard scan examples/sample_app
```

```
=== AccessGuard Report ===

Summary:
  Routes scanned: 6
  Risks found: 4 HIGH / 0 MEDIUM / 0 LOW

Risks:
  [HIGH] GET /users (score: 6)
    Potential privilege escalation: route '/users' accesses sensitive operation
    'billing_service.get_data'. Verify this is intended.

  [HIGH] POST /contact (score: 6)
    Potential privilege escalation: route '/contact' accesses sensitive operation
    'admin_service.reset_system'. Verify this is intended.
```

---

## What It Detects

- **Domain mismatch** — routes reaching services outside their expected scope
- **Privilege escalation** — unprivileged routes accessing admin or sensitive operations
- **Multi-hop paths** — risks that only appear 2–3 function calls deep

---

## Installation

**Option 1 — pip (recommended)**
```bash
pip install -e .
```

**Option 2 — Poetry**
```bash
poetry install
```

---

## Usage

```bash
accessguard scan <path>
accessguard init
```

**Examples**
```bash
accessguard scan .
accessguard scan ./backend
accessguard scan examples/sample_app
accessguard init
```

**Flags**

| Flag | Description |
|------|-------------|
| `--json` | Output results as JSON |
| `--quiet` | Show only detected risks, suppress summary |
| `--fail-on-high` | Exit with code `1` if any HIGH risks are found (useful in CI) |

---

## Configuration

AccessGuard supports project-level configuration via `accessguard.yaml` in the project root.

Use this command to create a starter config file:

```bash
accessguard init
```

When you run:

```bash
accessguard scan .
```

AccessGuard automatically loads `accessguard.yaml` if present. If no config file exists, AccessGuard falls back to built-in defaults.

**Default config format**

```yaml
sensitive_keywords:
  - billing
  - token
  - auth
  - secret

high_privilege_keywords:
  - admin
  - delete
  - reset
  - token
  - decrypt
  - billing

safe_routes:
  - auth
  - callback
  - oauth
  - login
```

**Init behavior**

- Creates `accessguard.yaml` in the current directory
- Does not overwrite an existing `accessguard.yaml`
- Prints a success/info message in both cases

---

## Ignoring Paths

Create a `.accessguardignore` file in your project root to exclude files or directories from analysis (same syntax as `.gitignore`).

---

## How It Works

1. **Parses** Python source files using the `ast` module
2. **Extracts** HTTP route handlers and all reachable function/method calls
3. **Builds** a cross-file call graph
4. **Traverses** the graph from each route, following multi-hop chains
5. **Flags** paths that reach sensitive operations based on deterministic risk rules

---

## Real-World Example (NudgePe)

AccessGuard was run against NudgePe, a real Python backend with 25+ routes:

- **25** routes analyzed
- **1** HIGH risk detected
- OAuth/token flows correctly classified as LOW

```
[HIGH] POST /{reminder_id}/send-now
  Potential privilege escalation: route accesses sensitive operation 'decrypt'
```

---

## Limitations

AccessGuard is a **static analysis tool** — it has no runtime context. Keep in mind:

- Name-based call resolution can miss dynamic imports or metaprogramming patterns
- Heuristic keyword matching may produce false positives or false negatives
- Designed for Python backends; other languages are not currently supported
- Large or complex codebases may need tuning of the sensitive-keyword list

---

## Roadmap

- [ ] Improved symbol and import resolution
- [ ] Better authentication-aware classification
- [ ] Expanded framework support (beyond Flask/FastAPI patterns)
- [ ] CI/CD integration and stable PyPI release

---

## Contributing

Pull requests are welcome. If you find a false positive or a missed detection on a real codebase, opening an issue with a minimal repro is the most helpful contribution you can make.

---

## License

MIT
