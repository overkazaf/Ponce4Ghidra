"""Triton concolic execution backend for Ponce4Ghidra.

Triton follows ONE concrete path while tracking symbolic state, then negates
branch conditions to explore alternatives. This is fundamentally different from
angr's approach of forking all paths simultaneously.

Requires: pip install triton-library lief
Both are optional — the server falls back to angr when they are missing.
"""
import logging
import time

logger = logging.getLogger("ponce4ghidra")

try:
    import triton
    import lief

    TRITON_AVAILABLE = True
except ImportError:
    TRITON_AVAILABLE = False


def _align(size: int, alignment: int = 0x100) -> int:
    return (size + alignment - 1) // alignment * alignment


# Architecture mapping: Triton arch enum, pointer size, calling-convention regs
_ARCH_MAP = {
    "x86_64": {
        "triton": "ARCH.X86_64" if TRITON_AVAILABLE else None,
        "word": 8,
        "arg_regs": ("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
        "sp": "rsp",
        "ip": "rip",
        "ret": "rax",
    },
    "x86": {
        "triton": "ARCH.X86" if TRITON_AVAILABLE else None,
        "word": 4,
        "arg_regs": (),
        "sp": "esp",
        "ip": "eip",
        "ret": "eax",
    },
    "aarch64": {
        "triton": "ARCH.AARCH64" if TRITON_AVAILABLE else None,
        "word": 8,
        "arg_regs": ("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"),
        "sp": "sp",
        "ip": "pc",
        "ret": "x0",
    },
}


class TritonEngine:
    """Concolic execution engine using Triton.

    Same protocol interface as SymbolicEngine (angr backend) so the server can
    swap them transparently.
    """

    def __init__(self):
        self.ctx = None
        self.binary_path: str | None = None
        self.binary = None  # lief parsed binary
        self.arch_info: dict | None = None
        self.find_addrs: list[int] = []
        self.avoid_addrs: list[int] = []
        self.symbolic_vars: dict[str, object] = {}
        self.found_states: list[dict] = []
        self.command_log: list[dict] = []
        self._entry_point: int = 0
        self._start_addr: int | None = None
        self._stack_base: int = 0x7FFF0000

    def _log(self, cmd_type: str, params: dict):
        self.command_log.append({"type": cmd_type, "params": params})

    def _require_triton(self):
        if not TRITON_AVAILABLE:
            raise RuntimeError(
                "Triton is not installed. Install with: "
                "pip install triton-library lief"
            )

    def init(self, binary_path: str) -> dict:
        self._require_triton()

        self.ctx = None
        self.binary = None
        self.binary_path = None
        self.symbolic_vars.clear()
        self.find_addrs.clear()
        self.avoid_addrs.clear()
        self.found_states.clear()
        self.command_log.clear()

        binary = lief.parse(binary_path)
        if binary is None:
            raise ValueError(f"Failed to parse binary: {binary_path}")

        arch_name = self._detect_arch(binary)
        arch_info = _ARCH_MAP.get(arch_name)
        if arch_info is None:
            raise ValueError(
                f"Unsupported architecture: {arch_name}. "
                f"Triton supports: {list(_ARCH_MAP.keys())}"
            )

        triton_arch = getattr(triton.ARCH, arch_name.upper(), None)
        if triton_arch is None:
            raise ValueError(f"Triton has no arch: {arch_name}")

        ctx = triton.TritonContext(triton_arch)
        ctx.setMode(triton.MODE.ALIGNED_MEMORY, True)
        ctx.setMode(triton.MODE.CONSTANT_FOLDING, True)

        self._load_segments(ctx, binary)

        self.ctx = ctx
        self.binary = binary
        self._binary_obj = binary
        self._triton_arch = triton_arch
        self.arch_info = arch_info
        self.binary_path = binary_path
        self._entry_point = binary.entrypoint
        self._start_addr = None
        self._stack_base = arch_info.get("stack", 0x7fff0000)

        is_library = False
        if isinstance(binary, lief.ELF.Binary):
            is_library = "DYN" in str(binary.header.file_type)
        elif isinstance(binary, lief.MachO.Binary):
            is_library = "DYLIB" in str(binary.header.file_type)

        self._log("init", {"binary_path": binary_path})
        logger.info("Triton: loaded %s (%s)", binary_path, arch_name)
        return {
            "arch": arch_name.upper(),
            "entry": hex(self._entry_point),
            "binary": binary_path,
            "is_library": is_library,
            "hooked_imports": [],
            "engine": "triton",
        }

    def _detect_arch(self, binary) -> str:
        if isinstance(binary, lief.ELF.Binary):
            machine = str(binary.header.machine_type)
            if "X86_64" in machine:
                return "x86_64"
            if "I386" in machine or "X86" in machine:
                return "x86"
            if "AARCH64" in machine:
                return "aarch64"
            if "ARM" in machine:
                return "arm32"
        elif isinstance(binary, lief.MachO.Binary):
            cpu = str(binary.header.cpu_type)
            if "X86_64" in cpu:
                return "x86_64"
            if "ARM64" in cpu or "AARCH64" in cpu:
                return "aarch64"
            if "ARM" in cpu:
                return "arm32"
        raise ValueError(f"Cannot detect architecture from binary")

    def _load_segments(self, ctx, binary):
        if isinstance(binary, lief.ELF.Binary):
            for seg in binary.segments:
                if "LOAD" in str(seg.type) and seg.physical_size > 0:
                    content = list(seg.content)
                    ctx.setConcreteMemoryAreaValue(seg.virtual_address, content)
        elif isinstance(binary, lief.MachO.Binary):
            for seg in binary.segments:
                if seg.virtual_size > 0 and len(seg.content) > 0:
                    ctx.setConcreteMemoryAreaValue(seg.virtual_address, list(seg.content))
        else:
            raise ValueError("Unsupported binary format for Triton")

    def _get_register(self, name: str):
        return self.ctx.getRegister(name)

    def _setup_stack(self):
        sp_reg = self._get_register(self.arch_info["sp"])
        self.ctx.setConcreteRegisterValue(sp_reg, self._stack_base)

    def symbolize_register(self, reg_name: str, state_addr: int) -> dict:
        self._require_ctx()
        reg = self._get_register(reg_name)
        sym = self.ctx.symbolizeRegister(reg)
        alias = f"sym_{reg_name}"
        sym.setAlias(alias)
        self.symbolic_vars[alias] = sym
        self._log("symbolize_register", {"reg_name": reg_name, "state_addr": state_addr})
        logger.info("Triton: symbolized register %s", reg_name)
        return {"name": alias, "bits": reg.getBitSize()}

    def symbolize_memory(self, addr: int, size: int, state_addr: int) -> dict:
        self._require_ctx()
        name = f"mem_{addr:#x}_{size}"
        for i in range(size):
            cell = triton.MemoryAccess(addr + i, 1)
            sym = self.ctx.symbolizeMemory(cell)
            sym.setAlias(f"{name}_{i}")
        self.symbolic_vars[name] = (addr, size)
        self._log("symbolize_memory", {"addr": addr, "size": size, "state_addr": state_addr})
        logger.info("Triton: symbolized memory at %#x (%d bytes)", addr, size)
        return {"name": name, "bits": size * 8, "addr": hex(addr)}

    def symbolize_function_argument(
        self,
        func_addr: int,
        reg_name: str = "rdi",
        size: int = 8,
        name: str | None = None,
    ) -> dict:
        self._require_ctx()
        var_name = name or f"arg_{reg_name}"
        self.symbolic_vars.clear()
        self.found_states.clear()

        self._setup_stack()
        self._start_addr = func_addr
        ip_reg = self._get_register(self.arch_info["ip"])
        self.ctx.setConcreteRegisterValue(ip_reg, func_addr)

        buf_addr = 0x70000000
        for i in range(size):
            self.ctx.setConcreteMemoryValue(buf_addr + i, 0x41)
            cell = triton.MemoryAccess(buf_addr + i, 1)
            sym = self.ctx.symbolizeMemory(cell)
            sym.setAlias(f"{var_name}_{i}")
        self.ctx.setConcreteMemoryValue(buf_addr + size, 0)

        arg_reg = self._get_register(reg_name)
        self.ctx.setConcreteRegisterValue(arg_reg, buf_addr)

        self.symbolic_vars[var_name] = (buf_addr, size)
        self._log("symbolize_function_arg", {
            "func_addr": func_addr, "reg_name": reg_name,
            "size": size, "name": name,
        })
        logger.info(
            "Triton: symbolized %s of function %#x -> %d bytes at %#x",
            reg_name, func_addr, size, buf_addr,
        )
        return {
            "name": var_name,
            "bits": size * 8,
            "addr": hex(buf_addr),
            "register": reg_name,
            "func_addr": hex(func_addr),
        }

    def symbolize_argv(
        self, size: int = 8, index: int = 1, name: str | None = None
    ) -> dict:
        self._require_ctx()
        if index < 1:
            raise ValueError("argv index must be at least 1")

        var_name = name or f"argv{index}"
        self.symbolic_vars.clear()
        self.found_states.clear()

        self._setup_stack()
        self._start_addr = self._entry_point
        ip_reg = self._get_register(self.arch_info["ip"])
        self.ctx.setConcreteRegisterValue(ip_reg, self._entry_point)

        word = self.arch_info["word"]
        buf_addr = 0x7FFFFFFFFFEF000
        argv_addr = 0x7FFFFFFFFFE0000
        path_addr = 0x7FFFFFFFFFD0000

        path_str = b"program\x00"
        for i, b in enumerate(path_str):
            self.ctx.setConcreteMemoryValue(path_addr + i, b)

        for i in range(size):
            self.ctx.setConcreteMemoryValue(buf_addr + i, 0x41)
            cell = triton.MemoryAccess(buf_addr + i, 1)
            sym = self.ctx.symbolizeMemory(cell)
            sym.setAlias(f"{var_name}_{i}")
        self.ctx.setConcreteMemoryValue(buf_addr + size, 0)

        entries = [path_addr] + [path_addr + len(path_str) - 1] * (index - 1) + [buf_addr, 0]
        for slot, ptr in enumerate(entries):
            for byte_i in range(word):
                self.ctx.setConcreteMemoryValue(
                    argv_addr + slot * word + byte_i,
                    (ptr >> (byte_i * 8)) & 0xFF
                )

        arg_regs = self.arch_info["arg_regs"]
        if len(arg_regs) >= 2:
            self.ctx.setConcreteRegisterValue(
                self._get_register(arg_regs[0]), index + 1)
            self.ctx.setConcreteRegisterValue(
                self._get_register(arg_regs[1]), argv_addr)

        self.symbolic_vars[var_name] = (buf_addr, size)
        self._log("symbolize_argv", {"size": size, "index": index, "name": name})
        logger.info("Triton: symbolized argv[%d] -> %d bytes at %#x", index, size, buf_addr)
        return {
            "name": var_name,
            "bits": size * 8,
            "addr": hex(buf_addr),
            "index": index,
        }

    def set_find(self, addresses: list[int]) -> dict:
        self.find_addrs = addresses
        self._log("set_find", {"addresses": [hex(a) for a in addresses]})
        logger.info("Triton: find addresses set: %s", [hex(a) for a in addresses])
        return {"find_count": len(self.find_addrs)}

    def set_avoid(self, addresses: list[int]) -> dict:
        self.avoid_addrs = addresses
        self._log("set_avoid", {"addresses": [hex(a) for a in addresses]})
        logger.info("Triton: avoid addresses set: %s", [hex(a) for a in addresses])
        return {"avoid_count": len(self.avoid_addrs)}

    def explore(self, timeout_sec: int = 60, progress_callback=None,
                use_veritesting: bool = False, use_unicorn: bool = False) -> dict:
        """Concolic exploration: execute concretely, negate branches to find paths.

        Strategy: run the function with concrete input, collecting branch
        constraints. When the path misses the target, negate one branch at a
        time to steer toward Find addresses. Each attempt creates a fresh
        TritonContext (Triton accumulates state that cannot be cleanly reset).
        """
        if self.ctx is None:
            raise ValueError("Engine is not initialized: no binary is loaded.")
        if not self.find_addrs:
            raise ValueError("No find addresses set. Call set_find first.")

        start = self._start_addr or self._entry_point
        ret_addr = 0xdeadbeef

        found_count = 0
        avoided_count = 0
        errored_count = 0
        total_steps = 0
        max_attempts = 64
        max_instructions = 500_000
        deadline = time.monotonic() + timeout_sec
        t0 = time.monotonic()
        last_report = time.monotonic()
        pending_models = []

        # Concrete input values — updated by models between attempts
        concrete_bufs = {}
        for var_name, var_info in self.symbolic_vars.items():
            if isinstance(var_info, tuple):
                buf_addr, size = var_info
                concrete_bufs[var_name] = [
                    self.ctx.getConcreteMemoryValue(buf_addr + i) for i in range(size)
                ]

        for attempt in range(max_attempts):
            if time.monotonic() >= deadline:
                break

            # Fresh context each attempt — Triton accumulates constraints
            # and symbolic expressions that pollute subsequent runs.
            ctx = triton.TritonContext(self._triton_arch)
            ctx.setMode(triton.MODE.ALIGNED_MEMORY, True)
            self._load_segments(ctx, self._binary_obj)

            # Set up the input buffer with current concrete values
            for var_name, var_info in self.symbolic_vars.items():
                if isinstance(var_info, tuple):
                    buf_addr, size = var_info
                    vals = concrete_bufs.get(var_name, [0x41] * size)
                    for i in range(size):
                        ctx.setConcreteMemoryValue(buf_addr + i, vals[i])
                    ctx.setConcreteMemoryValue(buf_addr + size, 0)
                    for i in range(size):
                        sym = ctx.symbolizeMemory(triton.MemoryAccess(buf_addr + i, 1))
                        sym.setAlias(f"{var_name}_{i}")

            ip_reg = ctx.getRegister(self.arch_info["ip"])
            sp_reg = ctx.getRegister(self.arch_info["sp"])
            ctx.setConcreteRegisterValue(ip_reg, start)
            ctx.setConcreteRegisterValue(sp_reg, self._stack_base)

            # Set up function argument register
            for var_name, var_info in self.symbolic_vars.items():
                if isinstance(var_info, tuple):
                    buf_addr, _ = var_info
                    arg_reg_name = self.arch_info["arg_regs"][0]
                    ctx.setConcreteRegisterValue(ctx.getRegister(arg_reg_name), buf_addr)

            # Return address on stack
            word = self.arch_info["word"]
            for i in range(word):
                ctx.setConcreteMemoryValue(self._stack_base + i, (ret_addr >> (i * 8)) & 0xFF)

            step_count = 0
            hit_find = False

            while step_count < max_instructions and time.monotonic() < deadline:
                pc = ctx.getConcreteRegisterValue(ip_reg)

                if pc in self.find_addrs:
                    found_count += 1
                    self.found_states.append({
                        "model": {
                            sym_id: ctx.getConcreteVariableValue(sym_var)
                            for sym_id, sym_var in ctx.getSymbolicVariables().items()
                        },
                        "path_constraints": list(ctx.getPathConstraints()),
                    })
                    # Save the winning concrete values back to self.ctx
                    for vn, vi in self.symbolic_vars.items():
                        if isinstance(vi, tuple):
                            ba, sz = vi
                            for i in range(sz):
                                v = ctx.getConcreteMemoryValue(ba + i)
                                self.ctx.setConcreteMemoryValue(ba + i, v)
                    logger.info("Triton: found target %#x on attempt %d (%d steps)",
                                pc, attempt + 1, step_count)
                    hit_find = True
                    break

                if pc in self.avoid_addrs:
                    avoided_count += 1
                    break

                if pc == ret_addr:
                    break

                inst = triton.Instruction(pc, bytes(ctx.getConcreteMemoryAreaValue(pc, 16)))
                try:
                    ctx.processing(inst)
                except Exception as e:
                    logger.warning("Triton: error at %#x: %s", pc, e)
                    errored_count += 1
                    break

                step_count += 1

                if inst.isBranch() and inst.isSymbolized():
                    pcs = ctx.getPathConstraints()
                    if pcs:
                        for branch in pcs[-1].getBranchConstraints():
                            if not branch["isTaken"]:
                                model = ctx.getModel(branch["constraint"])
                                if model:
                                    pending_models.append(model)

                now = time.monotonic()
                if progress_callback and now - last_report >= 1.0:
                    last_report = now
                    progress_callback({
                        "active": len(pending_models),
                        "found": found_count,
                        "avoided": avoided_count,
                        "steps": total_steps + step_count,
                        "elapsed": round(now - t0, 1),
                    })

            total_steps += step_count

            if hit_find:
                break
            if not pending_models:
                break

            model = pending_models.pop()
            for sym_id, sym_model in model.items():
                var = ctx.getSymbolicVariable(sym_id)
                origin = var.getOrigin()
                for vn, vi in self.symbolic_vars.items():
                    if isinstance(vi, tuple):
                        ba, sz = vi
                        idx = origin - ba
                        if 0 <= idx < sz:
                            concrete_bufs[vn][idx] = sym_model.getValue()

            logger.info("Triton: attempt %d, trying alternative (%d pending)",
                        attempt + 1, len(pending_models))

        return {
            "found_count": found_count,
            "active_count": len(pending_models),
            "avoided_count": avoided_count,
            "deadended_count": 0,
            "errored_count": errored_count,
            "error_samples": [],
            "explored_count": found_count,
        }

    def _capture_state(self) -> dict:
        """Snapshot the current context for later solving."""
        return {
            "path_constraints": list(self.ctx.getPathConstraints()),
            "model": {
                sym.getId(): self.ctx.getConcreteVariableValue(sym)
                for sym in self.ctx.getSymbolicVariables()
            },
        }

    def _apply_model(self, model):
        for sym_id, sym_model in model.items():
            var = self.ctx.getSymbolicVariable(sym_id)
            self.ctx.setConcreteVariableValue(var, sym_model.getValue())

    def solve(self, var_name: str) -> dict:
        raise ValueError("Use solve_all() — Triton solves all variables at once")

    def solve_all(self, max_solutions: int = 1) -> dict:
        self._require_ctx()
        if not self.found_states:
            raise ValueError(
                "No found state. Run explore first and ensure a Find target was reached."
            )
        if not self.symbolic_vars:
            raise ValueError(
                "Nothing is symbolized, so there is nothing to solve for. "
                "Symbolize a register or a memory region first, then explore again."
            )

        max_solutions = max(1, min(max_solutions, 256))
        solutions = {}

        for var_name, var_info in self.symbolic_vars.items():
            if isinstance(var_info, tuple):
                buf_addr, size = var_info
                entries = []
                for sol_idx in range(max_solutions):
                    concrete_bytes = []
                    for i in range(size):
                        val = self.ctx.getConcreteMemoryValue(buf_addr + i)
                        concrete_bytes.append(val)
                    value_int = int.from_bytes(concrete_bytes, "big")
                    entries.append({
                        "value_int": value_int,
                        "value_hex": hex(value_int),
                        "value_bytes": concrete_bytes,
                    })
                    if sol_idx == 0:
                        break
                solutions[var_name] = entries
            else:
                sym = var_info
                val = self.ctx.getConcreteVariableValue(sym)
                solutions[var_name] = [{
                    "value_int": val,
                    "value_hex": hex(val),
                    "value_bytes": list(val.to_bytes(
                        (val.bit_length() + 7) // 8 or 1, "big")),
                }]

        return {"solutions": solutions}

    def get_state(self) -> dict:
        return {
            "initialized": self.ctx is not None,
            "binary": self.binary_path,
            "variables": list(self.symbolic_vars.keys()),
            "find_addrs": [hex(a) for a in self.find_addrs],
            "avoid_addrs": [hex(a) for a in self.avoid_addrs],
            "found_count": len(self.found_states),
            "engine": "triton",
            "capabilities": {
                "veritesting": False,
                "unicorn": False,
                "triton": True,
            },
            "command_log": self.command_log,
        }

    def get_constraints(self, stash: str = "found", index: int = 0) -> dict:
        if not self.found_states:
            raise ValueError("No exploration results. Run explore first.")
        if index >= len(self.found_states):
            raise ValueError(
                f"State index {index} out of range "
                f"(found has {len(self.found_states)} states)"
            )

        path_constraints = self.found_states[index].get("path_constraints", [])
        result = []
        for pc in path_constraints:
            for branch in pc.getBranchConstraints():
                if branch["isTaken"]:
                    c = branch["constraint"]
                    result.append({
                        "text": str(c),
                        "op": "branch",
                        "depth": 0,
                        "variables": [],
                    })

        return {
            "constraints": result,
            "stash": stash,
            "index": index,
            "total_states": len(self.found_states),
        }

    def negate_branch(self, branch_addr: int) -> dict:
        raise ValueError("negate_branch is not yet implemented for the Triton backend")

    def replay(self, log: list[dict]) -> dict:
        replayed = 0
        for entry in log:
            cmd_type = entry["type"]
            params = entry.get("params", {})
            if cmd_type == "init":
                self.init(params["binary_path"])
            elif cmd_type == "set_find":
                addrs = [int(a, 16) if isinstance(a, str) else a
                         for a in params["addresses"]]
                self.set_find(addrs)
            elif cmd_type == "set_avoid":
                addrs = [int(a, 16) if isinstance(a, str) else a
                         for a in params["addresses"]]
                self.set_avoid(addrs)
            elif cmd_type == "symbolize_register":
                self.symbolize_register(
                    params["reg_name"], params.get("state_addr", 0))
            elif cmd_type == "symbolize_memory":
                self.symbolize_memory(
                    params["addr"], params["size"], params.get("state_addr", 0))
            elif cmd_type == "symbolize_function_arg":
                self.symbolize_function_argument(
                    params["func_addr"], params.get("reg_name", "rdi"),
                    params.get("size", 8), params.get("name"))
            elif cmd_type == "symbolize_argv":
                self.symbolize_argv(
                    params.get("size", 8), params.get("index", 1),
                    params.get("name"))
            else:
                logger.warning("Skipping unknown replay command: %s", cmd_type)
                continue
            replayed += 1
        return {"replayed": replayed, "total": len(log)}

    def _require_ctx(self):
        if self.ctx is None:
            raise ValueError(
                "Engine is not initialized: no binary is loaded. "
                "Run 'init' with a binary path first."
            )

    def _require_project(self):
        return self._require_ctx()
