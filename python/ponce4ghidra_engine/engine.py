import logging
from typing import Any

import angr
import archinfo
import claripy
from angr.simos import SimUserland

logger = logging.getLogger("ponce4ghidra")


def _align(size: int, alignment: int = 0x100) -> int:
    return (size + alignment - 1) // alignment * alignment


class SymbolicEngine:
    def __init__(self):
        self.project: angr.Project | None = None
        self.state: angr.SimState | None = None
        self.simgr: angr.SimulationManager | None = None
        self.symbolic_vars: dict[str, claripy.ast.BV] = {}
        self.find_addrs: list[int] = []
        self.avoid_addrs: list[int] = []
        # Which binary is loaded, so the plugin can ask instead of guessing.
        self.binary_path: str | None = None
        self.command_log: list[dict] = []

    def _log(self, cmd_type: str, params: dict):
        self.command_log.append({"type": cmd_type, "params": params})

    def init(self, binary_path: str) -> dict:
        """Load `binary_path`, discarding everything held for whatever was loaded before.

        The clear() calls below are the reason callers must not re-init for a
        binary that is already loaded: they take the symbolized variables with
        them, and those exist nowhere else. The plugin decides whether to call
        this by asking get_state() for `binary` rather than trusting its own
        record of what it last sent.
        """
        # Drop any previous project first: if angr.Project() raises below we must
        # not be left holding a stale project/state pair.
        self.project = None
        self.state = None
        self.simgr = None
        self.binary_path = None

        self.project = angr.Project(binary_path, auto_load_libs=False)
        hooked_imports = self._hook_macho_imports()

        main_obj = self.project.loader.main_object
        is_library = (
            getattr(main_obj, "is_shared_object", False)
            or self.project.entry == 0
            or getattr(main_obj, "filetype", "") == "ET_DYN"
        )

        if is_library:
            logger.info(
                "Binary is a shared library — deferring state creation until "
                "a function is selected for analysis."
            )
        else:
            self.state = self.project.factory.entry_state()
            self.simgr = self.project.factory.simulation_manager(self.state)

        self.symbolic_vars.clear()
        self.find_addrs.clear()
        self.avoid_addrs.clear()
        self.command_log.clear()
        self.binary_path = binary_path
        self._log("init", {"binary_path": binary_path})
        logger.info("Loaded binary: %s (%s)", binary_path, self.project.arch.name)
        return {
            "arch": self.project.arch.name,
            "entry": hex(self.project.entry),
            "binary": binary_path,
            "is_library": is_library,
            "hooked_imports": hooked_imports,
        }

    def _hook_macho_imports(self) -> list[str]:
        """Hook a Mach-O binary's imports so that calls into libc still work.

        Mach-O calls reach libc through __stubs -> __got -> an address inside
        CLE's "extern object". angr ships no Mach-O SimOS -- angr/simos has
        linux, windows, cgc and javavm only -- so nothing installs the libc
        SimProcedures the way SimLinux does for ELF. The extern object is also
        mapped for its first symbol only, so the second import sits just past
        the end of it and any state that calls it dies with "IR decoding error
        at <first import + 8>". Back in the plugin that shows up as a silent
        "0 paths found", which is impossible to diagnose from the UI.

        The relocation table gives the exact symbol -> address mapping, so hook
        each import where the loader resolved it. Imports with no SimProcedure
        get ReturnUnconstrained, so an unknown libc call forks on its return
        value instead of killing the path.
        """
        main = self.project.loader.main_object
        if type(main).__name__ != "MachO":
            # ELF/PE get their libc SimProcedures from their own SimOS.
            return []

        libc = angr.SIM_PROCEDURES.get("libc", {})
        fallback = angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]
        hooked = []
        for reloc in getattr(main, "relocs", []):
            symbol = getattr(reloc, "symbol", None)
            if symbol is None or not getattr(symbol, "is_import", False):
                continue
            addr = reloc.value
            if not isinstance(addr, int) or addr == 0 or self.project.is_hooked(addr):
                continue
            # Mach-O symbols carry a leading underscore: _printf -> printf.
            proc = libc.get((symbol.name or "").lstrip("_"), fallback)
            self.project.hook(addr, proc())
            hooked.append(symbol.name)

        if hooked:
            logger.info("Hooked Mach-O imports: %s", ", ".join(hooked))
        return hooked

    def symbolize_register(self, reg_name: str, state_addr: int) -> dict:
        state = self._ensure_state(state_addr)
        size = state.arch.registers.get(reg_name)
        if size is None:
            raise ValueError(f"Unknown register: {reg_name}")
        bits = size[1] * 8
        sym_var = claripy.BVS(f"sym_{reg_name}", bits)
        self.symbolic_vars[reg_name] = sym_var
        setattr(state.regs, reg_name, sym_var)
        self._log("symbolize_register", {"reg_name": reg_name, "state_addr": state_addr})
        logger.info("Symbolized register %s (%d bits) at 0x%x", reg_name, bits, state_addr)
        return {"name": reg_name, "bits": bits}

    def symbolize_memory(self, addr: int, size: int, state_addr: int) -> dict:
        state = self._ensure_state(state_addr)
        name = f"mem_{addr:#x}_{size}"
        self._symbolize_buffer(state, addr, size, name)
        self._log("symbolize_memory", {"addr": addr, "size": size, "state_addr": state_addr})
        logger.info("Symbolized memory at 0x%x (%d bytes)", addr, size)
        return {"name": name, "bits": size * 8, "addr": hex(addr)}

    # ------------------------------------------------------------------ setup
    # Entry points that build a *new* starting state for the search, rather than
    # tweaking the one angr's entry_state() produced.

    # Which registers carry argc/argv/envp at the entry point.
    ARGV_REGISTERS = {
        "AMD64": ("rdi", "rsi", "rdx"),
        "X86": ("eax", "ecx", "edx"),
        "AARCH64": ("x0", "x1", "x2"),
        "ARM": ("r0", "r1", "r2"),
        "MIPS32": ("a0", "a1", "a2"),
        "MIPS64": ("a0", "a1", "a2"),
    }

    def symbolize_function_argument(
        self,
        func_addr: int,
        reg_name: str = "rdi",
        size: int = 8,
        name: str | None = None,
    ) -> dict:
        """Start from `func_addr` with an argument register aimed at a symbolic buffer.

        The alternative -- exploring from the entry point -- only works if the
        path you care about is reachable from there. Starting at the function
        itself skips everything that has to happen first, and a symbolic argument
        is what makes a function that branches on its input produce more than one
        path.
        """
        project = self._require_project()
        self._check_buffer_size(size)
        self._check_writable_register(project, reg_name)

        # call_state rather than blank_state: it leaves a return address on the
        # stack, so the function can return instead of running off into whatever
        # happens to sit above it.
        state = project.factory.call_state(func_addr)
        if state.solver.symbolic(state.regs.sp):
            raise ValueError(
                "The stack pointer at this function is symbolic, so there is "
                "nowhere to put the buffer."
            )

        # Adopt before symbolizing: adopting clears the variables of the state
        # being replaced, which would otherwise take the new buffer with it.
        self._adopt(state)

        var_name = name or f"arg_{reg_name}"
        buf_addr = self._scratch_address(size + 1)
        self._symbolize_buffer(state, buf_addr, size, var_name, terminate=True)
        setattr(state.regs, reg_name, buf_addr)

        self._log("symbolize_function_arg", {
            "func_addr": func_addr, "reg_name": reg_name, "size": size, "name": var_name,
        })
        logger.info(
            "Symbolized %s of function %#x -> %d bytes at %#x",
            reg_name, func_addr, size, buf_addr,
        )
        return {
            "name": var_name,
            "bits": size * 8,
            "addr": hex(buf_addr),
            "register": reg_name,
            "func_addr": hex(func_addr),
        }

    def symbolize_argv(self, size: int = 8, index: int = 1, name: str | None = None) -> dict:
        """Start from the entry point with argv[index] aimed at a symbolic buffer.

        This is the whole-program counterpart to symbolize_function_argument: the
        search runs from the entry point, so whatever the program does before it
        reaches the input is part of the path.
        """
        project = self._require_project()
        self._check_buffer_size(size)
        if index < 1:
            raise ValueError(
                "argv index must be at least 1: argv[0] is the program path, "
                "not something the program reads as input."
            )

        path = (project.filename or "program").encode()
        state, buf_addr = self._argv_state(project, path, index, size)

        # Adopt before symbolizing: see symbolize_function_argument.
        self._adopt(state)

        var_name = name or f"argv{index}"
        self._symbolize_buffer(state, buf_addr, size, var_name, terminate=True)

        self._log("symbolize_argv", {"size": size, "index": index, "name": var_name})
        logger.info("Symbolized argv[%d] -> %d bytes at %#x", index, size, buf_addr)
        return {
            "name": var_name,
            "bits": size * 8,
            "addr": hex(buf_addr),
            "index": index,
        }

    def _argv_state(self, project: angr.Project, path: bytes, index: int, size: int):
        """An entry state whose argv[index] is a buffer we can overwrite."""
        if isinstance(project.simos, SimUserland):
            # Linux and Windows SimOSes build a real argc/argv/envp stack. Hand
            # that machinery the argument list and retarget the buffer it already
            # allocated, instead of writing a second argv array the rest of the
            # stack layout knows nothing about.
            args = [path.decode(errors="replace")] + ["A" * size] * index
            state = project.factory.entry_state(args=args)
            argv = getattr(getattr(state, "posix", None), "argv", None)
            if argv is not None and len(argv) > index:
                return state, state.solver.eval(argv[index])
            logger.warning(
                "The SimOS did not lay out argv, so the engine is building the "
                "argument array itself."
            )
        return self._manual_argv_state(project, path, index, size)

    def _manual_argv_state(self, project: angr.Project, path: bytes, index: int, size: int):
        """Build argc/argv by hand, for a SimOS that leaves an empty stack.

        angr ships no Mach-O SimOS, so entry_state() there is a bare state at the
        entry point -- and entry_state(args=...) is accepted and then ignored.
        main() still expects argv where the C runtime would have left it, so put
        the strings and the pointer array below rsp, inside the stack region angr
        maps and clear of the frame the program is about to build.
        """
        regs = self.ARGV_REGISTERS.get(project.arch.name)
        if regs is None:
            raise ValueError(
                f"Symbolizing argv is not implemented for {project.arch.name}: "
                "the engine does not know which registers carry argc and argv."
            )

        state = project.factory.entry_state()
        if state.solver.symbolic(state.regs.sp):
            raise ValueError(
                "The stack pointer at the entry point is symbolic, so there is "
                "nowhere to lay out argv."
            )
        rsp = state.solver.eval(state.regs.sp)

        # Laid out downwards, each block aligned so that a large buffer cannot
        # run into the pointer array or the path string below it.
        word = project.arch.bytes
        gap = 0x1000
        buf_addr = rsp - gap
        gap += _align(size + 1)
        argv_addr = rsp - gap
        gap += _align((index + 2) * word)
        path_addr = rsp - gap

        self._store_bytes(state, path_addr, path + b"\x00")
        # Slots below the one we care about point at the path's terminator, which
        # reads as an empty string -- better than handing the program a pointer
        # into whatever else is on the stack.
        entries = [path_addr] + [path_addr + len(path)] * (index - 1) + [buf_addr, 0]
        for slot, pointer in enumerate(entries):
            self._store_word(state, argv_addr + slot * word, pointer)

        setattr(state.regs, regs[0], index + 1)  # argc
        setattr(state.regs, regs[1], argv_addr)  # argv
        setattr(state.regs, regs[2], 0)  # envp
        return state, buf_addr

    # ----------------------------------------------------------------- helpers

    def _adopt(self, state) -> None:
        """Make `state` the one later commands act on.

        Both halves of the old state go. Its exploration result describes a
        search that no longer applies, and the variables symbolized against it
        live in its registers and memory -- keeping them would have solve_all()
        report values for a state the search never ran on.
        """
        dropped = sorted(self.symbolic_vars)
        if dropped:
            logger.info(
                "Dropping variables that belong to the replaced state: %s",
                ", ".join(dropped),
            )
        self.symbolic_vars.clear()
        self.state = state
        self.simgr = None

    def _symbolize_buffer(
        self, state, addr: int, size: int, name: str, terminate: bool = False
    ) -> claripy.ast.BV:
        """Create a `size`-byte symbolic buffer at `addr`.

        Stored big-endian on purpose. That makes the variable's big-endian byte
        order equal to address order, which is the order solve_all() reports
        values in -- reversing it here would make the plugin print passwords
        backwards. (It is also the memory plugin's own default; saying so
        explicitly keeps that from changing under us.)
        """
        sym_var = claripy.BVS(name, size * 8)
        self.symbolic_vars[name] = sym_var
        state.memory.store(addr, sym_var, endness=archinfo.Endness.BE)
        if terminate:
            # One NUL just past the buffer, so a strlen-style argument reads
            # exactly `size` bytes and not the rest of the page.
            state.memory.store(addr + size, claripy.BVV(0, 8))
        return sym_var

    def _store_word(self, state, addr: int, value: int) -> None:
        """Store an integer so the target loads back the value we stored.

        state.memory.store() defaults to the *memory plugin's* endness, which is
        big-endian whatever the target is, while VEX Load/Store follow the
        *architecture's* endness. A pointer written with the default therefore
        reaches the target byte-reversed -- on x86-64 the argument 0x7fffffffffef000
        arrives as 0xf0feffffffff07, which points somewhere else entirely and
        turns a solvable program into an unsolvable one. Anything the target
        loads as a multi-byte value has to go through here.
        """
        state.memory.store(
            addr,
            claripy.BVV(value, state.arch.bits),
            endness=state.arch.memory_endness,
        )

    def _store_bytes(self, state, addr: int, data: bytes) -> None:
        """Store concrete bytes, one memory byte per byte of `data`.

        A single-byte store reads back the same under either endness, so unlike
        _store_word this cannot disagree with the target.
        """
        for offset, byte in enumerate(data):
            state.memory.store(addr + offset, claripy.BVV(byte, 8))

    def _scratch_address(self, size: int) -> int:
        """A writable address that collides with nothing the loader mapped.

        angr gives this engine no allocator, so pick the first candidate base no
        loaded object overlaps. Every candidate sits far below the stack, which
        angr puts near the top of the address space.
        """
        taken = [(o.min_addr, o.max_addr + 1) for o in self._require_project().loader.all_objects]
        for base in (0x70000000, 0x80000000, 0x1000000000, 0x2000000000):
            if all(base + size <= start or base >= end for start, end in taken):
                return base
        raise ValueError(
            f"No free address for a {size}-byte buffer: every candidate base "
            "collides with an object the loader mapped."
        )

    def _check_buffer_size(self, size: int) -> None:
        if size <= 0:
            raise ValueError(f"Buffer size must be positive, got {size}.")

    def _check_writable_register(self, project: angr.Project, reg_name: str) -> None:
        if reg_name not in project.arch.registers:
            raise ValueError(f"Unknown register: {reg_name}")
        names = project.arch.register_names
        for offset in (project.arch.ip_offset, project.arch.sp_offset):
            if reg_name == names.get(offset):
                # Pointing either of these at a buffer destroys the call frame
                # the state was just set up with.
                raise ValueError(
                    f"{reg_name} holds the instruction or stack pointer; it "
                    "cannot carry a function argument."
                )

    def set_find(self, addresses: list[int]) -> dict:
        self.find_addrs = addresses
        self._log("set_find", {"addresses": [hex(a) for a in addresses]})
        logger.info("Find addresses set: %s", [hex(a) for a in addresses])
        self._warn_on_find_avoid_overlap()
        return {"find_count": len(self.find_addrs)}

    def set_avoid(self, addresses: list[int]) -> dict:
        self.avoid_addrs = addresses
        self._log("set_avoid", {"addresses": [hex(a) for a in addresses]})
        logger.info("Avoid addresses set: %s", [hex(a) for a in addresses])
        self._warn_on_find_avoid_overlap()
        return {"avoid_count": len(self.avoid_addrs)}

    def _warn_on_find_avoid_overlap(self) -> None:
        """Flag addresses that are both a find and an avoid target.

        angr checks find before avoid, so listing an address in both means the
        avoid entry silently does nothing -- the opposite of what the two lists
        look like they should do together.
        """
        both = sorted(set(self.find_addrs) & set(self.avoid_addrs))
        if both:
            logger.warning(
                "%s is set as both a find and an avoid target. angr checks find "
                "first, so the avoid entry has no effect.",
                ", ".join(hex(a) for a in both),
            )

    def explore(self, timeout_sec: int = 60, progress_callback=None,
                use_veritesting: bool = False,
                use_unicorn: bool = False) -> dict:
        project = self._require_project()
        state = self._require_state()

        if not self.find_addrs:
            raise ValueError("No find addresses set. Call set_find first.")

        if use_unicorn and self._has_unicorn():
            import angr.sim_options as o
            state.options.add(o.UNICORN)
            logger.info("Unicorn fast concrete execution enabled")

        import time as _time
        from angr.exploration_techniques import Timeout

        self.simgr = project.factory.simulation_manager(state)
        self.simgr.use_technique(Timeout(timeout=timeout_sec))

        if use_veritesting:
            from angr.exploration_techniques import Veritesting
            self.simgr.use_technique(Veritesting())
            logger.info("Veritesting enabled")

        step_count = [0]
        last_report = [_time.monotonic()]
        start = _time.monotonic()

        def _step(sm):
            step_count[0] += 1
            now = _time.monotonic()
            if progress_callback and now - last_report[0] >= 1.0:
                last_report[0] = now
                progress_callback({
                    "active": len(sm.active),
                    "found": len(sm.found),
                    "avoided": len(sm.stashes.get("avoid", [])),
                    "steps": step_count[0],
                    "elapsed": round(now - start, 1),
                })
            return sm

        self.simgr.explore(
            find=self.find_addrs,
            avoid=self.avoid_addrs if self.avoid_addrs else None,
            step_func=_step,
        )

        found_count = len(self.simgr.found)
        deadended_count = len(self._stash("deadended"))
        errored = list(self.simgr.errored)
        logger.info(
            "Exploration complete: %d found, %d active, %d avoided, %d deadended, %d errored",
            found_count,
            len(self.simgr.active),
            len(self._stash("avoided")),
            deadended_count,
            len(errored),
        )
        if found_count == 0 and errored:
            # Say why here. Otherwise this reads as an empty search and the only
            # clue left is a "no solution state" error from the next command.
            logger.warning(
                "No path reached a find address; every state died, e.g. %s",
                errored[0].error,
            )

        return {
            "found_count": found_count,
            "active_count": len(self.simgr.active),
            "avoided_count": len(self._stash("avoided")),
            "deadended_count": deadended_count,
            "errored_count": len(errored),
            "error_samples": [str(e.error) for e in errored[:3]],
            "explored_count": found_count + deadended_count,
        }

    def _stash(self, name: str) -> list:
        """Contents of a stash, for the stashes angr only creates on first use."""
        return self.simgr.stashes.get(name, []) if self.simgr else []

    def solve(self, var_name: str) -> dict:
        simgr = self._require_found()
        if var_name not in self.symbolic_vars:
            raise ValueError(f"Unknown symbolic variable: {var_name}")

        found_state = simgr.found[0]
        sym_var = self.symbolic_vars[var_name]
        concrete = found_state.solver.eval(sym_var)

        byte_len = sym_var.length // 8
        try:
            as_bytes = concrete.to_bytes(byte_len, "big")
            value_repr = repr(as_bytes)
        except (OverflowError, ValueError):
            value_repr = hex(concrete)

        return {
            "name": var_name,
            "value": hex(concrete),
            "value_bytes": value_repr,
            "bits": sym_var.length,
        }

    def solve_all(self, max_solutions: int = 1) -> dict:
        simgr = self._require_found()
        if not self.symbolic_vars:
            raise ValueError(
                "Nothing is symbolized, so there is nothing to solve for. "
                "Symbolize a register or a memory region first, then explore again."
            )

        max_solutions = max(1, min(max_solutions, 256))
        found_state = simgr.found[0]
        solutions = {}
        for name, sym_var in self.symbolic_vars.items():
            values = found_state.solver.eval_upto(sym_var, max_solutions)
            byte_len = sym_var.length // 8
            entries = []
            for concrete in values:
                try:
                    as_bytes = list(concrete.to_bytes(byte_len, "big"))
                except (OverflowError, ValueError):
                    as_bytes = []
                entries.append({
                    "value_int": concrete,
                    "value_hex": hex(concrete),
                    "value_bytes": as_bytes,
                })
            solutions[name] = entries

        return {"solutions": solutions}

    @staticmethod
    def _has_unicorn() -> bool:
        try:
            import unicorn  # noqa: F401
            return True
        except ImportError:
            return False

    def get_state(self) -> dict:
        found_count = 0
        if self.simgr and hasattr(self.simgr, '_stashes') and 'found' in self.simgr._stashes:
            found_count = len(self.simgr.found)
        return {
            "initialized": self.project is not None and self.state is not None,
            "binary": self.binary_path,
            "variables": list(self.symbolic_vars.keys()),
            "find_addrs": [hex(a) for a in self.find_addrs],
            "avoid_addrs": [hex(a) for a in self.avoid_addrs],
            "found_count": found_count,
            "capabilities": {
                "veritesting": True,
                "unicorn": self._has_unicorn(),
            },
            "command_log": self.command_log,
        }

    def get_constraints(self, stash: str = "found", index: int = 0) -> dict:
        if self.simgr is None:
            raise ValueError("No exploration results. Run explore first.")
        states = self.simgr.stashes.get(stash, [])
        if not states:
            raise ValueError(
                f"Stash '{stash}' is empty. Run explore first."
            )
        if index < 0 or index >= len(states):
            raise ValueError(
                f"State index {index} out of range "
                f"(stash '{stash}' has {len(states)} states)"
            )

        state = states[index]
        result = []
        for c in state.solver.constraints:
            raw = str(c)
            if raw.startswith("<Bool ") and raw.endswith(">"):
                raw = raw[6:-1]
            variables = sorted(c.variables) if hasattr(c, "variables") else []
            result.append({
                "text": raw,
                "op": getattr(c, "op", None),
                "depth": getattr(c, "depth", 0),
                "variables": variables,
            })

        return {
            "constraints": result,
            "stash": stash,
            "index": index,
            "total_states": len(states),
        }

    def replay(self, log: list[dict]) -> dict:
        """Replay a command log to recreate a session."""
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

    def negate_branch(self, branch_addr: int) -> dict:
        found_state = self._require_found().found[0]
        constraints = found_state.solver.constraints
        if not constraints:
            raise ValueError("No constraints to negate")

        last_constraint = constraints[-1]
        negated = claripy.Not(last_constraint)

        new_state = found_state.copy()
        new_state.solver.add(negated)

        if new_state.solver.satisfiable():
            self.state = new_state
            # Drop the old exploration result: it belongs to the un-negated state,
            # so solving against it would silently return the wrong answer.
            self.simgr = None
            return {"satisfiable": True, "branch_addr": hex(branch_addr)}

        return {"satisfiable": False, "branch_addr": hex(branch_addr)}

    def _require_project(self) -> angr.Project:
        if self.project is None:
            raise ValueError(
                "Engine is not initialized: no binary is loaded. "
                "Run 'init' with a binary path first."
            )
        return self.project

    def _require_state(self) -> angr.SimState:
        self._require_project()
        if self.state is None:
            raise ValueError("Engine has no state. Run 'init' first.")
        return self.state

    def _require_found(self) -> angr.SimulationManager:
        if self.simgr is None:
            raise ValueError("No solution state available. Run explore first.")
        if not self.simgr.found:
            raise ValueError(
                "No solution state available. Run explore first "
                "(the last exploration found no path to a find address)."
            )
        return self.simgr

    def _ensure_state(self, state_addr: int):
        project = self._require_project()
        if state_addr != 0 and (self.state is None or state_addr != self.state.addr):
            self.state = project.factory.blank_state(addr=state_addr)
            self.simgr = None
        if self.state is None:
            raise ValueError("Engine has no state. Run 'init' first.")
        return self.state
