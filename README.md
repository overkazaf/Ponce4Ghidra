[English](README.md) | [中文](README_CN.md)

# Ponce4Ghidra

Interactive symbolic execution plugin for Ghidra, powered by [angr](https://angr.io) + [Z3](https://github.com/Z3Prover/z3).

Right-click an address, symbolize the input, click Solve — the plugin finds concrete values that make the program reach your target. Passwords, license keys, flag checkers, crypto parameters — if it's a constraint satisfaction problem, Ponce4Ghidra solves it.

**[Project Page](https://overkazaf.github.io/Ponce4Ghidra/)** — architecture diagrams, workflow guide, and SAT/SMT primer.

## Quick Demo

```
1. Open test_crackme in Ghidra
2. Right-click 0x1000004d7 (return 1) → Set as Find Target
3. Right-click 0x100000484 (return 0) → Set as Avoid
4. Ponce4Ghidra → Symbolize argv[1] (size: 4)
5. Ponce4Ghidra → Solve Constraints
   → Solved: argv1 = P4Rg
```

### Constraints Tab — see how the solver derived the password

![Constraints Tab](docs/img/constraints-tab.png)

Each constraint maps to a byte of the password: `byte0 == 80 ('P')`, `byte1 == 52 ('4')`, `byte2 ^ 0x42 == 0x10 ('R')`, `byte3 + 0x20 == 0x87 ('g')`.

### Results Tab — 5 solutions for a 19-byte license key (ELF binary)

![Results Tab](docs/img/results-table.png)

Multi-solution enumeration on `test_license_elf`: the solver found 5 valid license keys, all variants of `K9mZ-4wR2-Xp7B-3nLf` differing in the last byte.

## Features

**Core**
- Symbolize argv, function arguments, registers, or memory regions
- Set Find/Avoid targets from Listing or Decompiler views
- Solve with up to 5 alternative solutions per variable
- Real-time exploration progress in the status bar

**Analysis**
- Constraints tab — see exactly which conditions the solver satisfied
- Veritesting — smart path merging at loop boundaries (enabled by default)
- Unicorn fast concrete execution (when installed)
- Timeout protection via angr's Timeout exploration technique

**Platform**
- Mach-O (macOS x86_64) — fully tested
- ELF (Linux x86_64) — tested with static binaries
- Android .so (ARM/ARM64) — deferred state creation for libraries without entry points
- ARM32, MIPS32/64 register support

**UX**
- Colored toolbar icons for all 8 actions
- Quick Start Guide with SAT/SMT primer (Help menu)
- Session persistence — Save/Restore across Ghidra restarts
- Pre-solve validation ("Nothing is symbolized" caught before explore)
- Stale engine detection (refuses to wipe variables against a mismatched engine)

## How It Works

```mermaid
flowchart LR
    A["🎯 Set Find/Avoid"] --> B["📝 Symbolize Input"]
    B --> C["🔀 angr: Fork at Branches"]
    C --> D["📋 Collect Constraints"]
    D --> E["🧮 Z3: Solve Equations"]
    E --> F["✅ P4Rg"]
```

> **Not brute force** — a 16-byte input has 2¹²⁸ possibilities. The constraints reduce it to a system Z3 solves in seconds.

## Architecture

```
┌─────────────┐    JSON/TCP    ┌──────────────────┐
│   Ghidra    │ ◄────────────► │   angr Engine    │
│   Plugin    │    port 13370  │   (Python)       │
│   (Java)    │                │                  │
│             │  commands:     │  angr.Project    │
│  Panel:     │  init          │  SimState        │
│  Variables  │  symbolize_*   │  SimulationMgr   │
│  Find/Avoid │  set_find/avoid│  explore()       │
│  Results    │  explore       │  solver.eval()   │
│  Constraints│  solve         │                  │
│             │  get_state     │  Z3 SMT Solver   │
│  Actions:   │  get_constraints                  │
│  8 menu     │  replay        │  Veritesting     │
│  items      │  set_options   │  Unicorn (opt)   │
└─────────────┘                └──────────────────┘
```

## When to Use Which Symbolize

| Method | Use when |
|--------|----------|
| **Symbolize argv[N]** | Program reads input from command line. Binary is small/simple. |
| **Symbolize Function Argument** | You know which function checks the input. Binary is large/complex. Analyzing a .so library. **Start here.** |
| **Symbolize Register** | The unknown is a scalar (int/long), not a buffer. |
| **Symbolize Memory** | The unknown is at a known fixed memory address. |

**Rule of thumb**: start with Function Argument (faster, targeted). Use argv only when you need the whole program's execution context.

## Installation

### Prerequisites

- [Ghidra](https://ghidra-sre.org/) 11.4+
- Java 17+ (JDK)
- Python 3.10+ with a virtual environment containing angr

### Setup

```bash
# 1. Create a Python venv with angr
python3 -m venv .venv
source .venv/bin/activate
pip install angr

# Optional: faster concrete execution
pip install unicorn

# 2. Build the Ghidra extension
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.4.3_PUBLIC
gradle buildExtension

# 3. Install in Ghidra
# Ghidra → File → Install Extensions → Add → select dist/*.zip
# Or manually unzip into ~/Library/ghidra/.../Extensions/
```

### Running

**Option A** — Let the plugin manage the engine (automatic):
Just use the plugin. It starts the engine process when needed.

**Option B** — Start the engine manually (for development):
```bash
cd Ponce4Ghidra
PYTHONPATH=python python3 -m ponce4ghidra_engine -v
```
The plugin connects to whatever is already on port 13370.

## Test Suite

```bash
# Run all tests (spawns engine instances on ports 13371+)
PYTHONPATH=python python3 test/test_engine.py
```

Tests:
- Direct angr symbolic execution
- Server protocol (init, symbolize, find/avoid, state)
- Uninitialized command guards
- Mach-O import hooking
- Function argument + argv symbolization (Mach-O)
- Re-init contract (stale engine protection)
- Explore progress reporting
- ELF function argument symbolization

## Test Binaries

| Binary | Format | Password/Key | Find | Avoid |
|--------|--------|-------------|------|-------|
| `test_crackme` | Mach-O x86_64 | `P4Rg` | 0x1000004d7 | 0x100000484 |
| `test_license` | Mach-O x86_64 | `K9mZ-4wR2-Xp7B-3nLf` | 0x100000a38 | 0x100000a4f |
| `test_license_elf` | ELF x86_64 (static) | `K9mZ-4wR2-Xp7B-3nLf` | 0x1017327 | 0x101731e |

## How It Works

Ponce4Ghidra uses **symbolic execution** — not brute force, not fuzzing.

1. **Symbolic variables** replace concrete input with math unknowns
2. Each branch adds a **constraint**: `if (input[0] == 'P')` → `byte0 == 0x50`
3. Both sides of every branch are explored simultaneously (**path forking**)
4. When a path reaches the Find target, all constraints go to **Z3** (an SMT solver)
5. Z3 finds concrete values satisfying all constraints — the password

A 16-byte input has 2¹²⁸ possibilities. The constraints reduce it to a system Z3 solves in seconds.

See the [SAT/SMT Primer](https://claude.ai/code/artifact/f821e2df-71f0-4d12-aea9-420d601d17f8) for the full explanation with architecture diagrams.

## License

MIT
