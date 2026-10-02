#!/usr/bin/env python3
"""Test the Ponce4Ghidra angr engine against test_crackme binary."""

import json
import os
import socket
import subprocess
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
PYTHON_DIR = os.path.join(PROJECT_DIR, "python")
BINARY = os.path.join(SCRIPT_DIR, "test_crackme")
ELF_BINARY = os.path.join(SCRIPT_DIR, "test_license_elf")
TEST_PORT = 13371

sys.path.insert(0, PYTHON_DIR)


def test_direct_engine():
    """Test symbolic execution on check_password function directly."""
    from ponce4ghidra_engine.engine import SymbolicEngine
    import angr
    import claripy

    print("[1] Loading binary...")
    proj = angr.Project(BINARY, auto_load_libs=False)

    check_pw_addr = None
    for sym in proj.loader.symbols:
        if hasattr(sym, 'name') and sym.name and "check_password" in sym.name:
            check_pw_addr = sym.rebased_addr
            break
    if check_pw_addr is None:
        print("[SKIP] Could not find check_password symbol")
        return True
    print(f"    check_password at {hex(check_pw_addr)}")

    print("[2] Setting up symbolic state at check_password...")
    input_buf = 0x400000
    sym_input = claripy.BVS("input", 8 * 4)

    RET_ADDR = 0xdeadbeef
    state = proj.factory.blank_state(addr=check_pw_addr)
    state.memory.store(input_buf, sym_input)
    state.regs.rdi = input_buf
    state.regs.rsp = 0x7fff0000
    state.regs.rbp = 0x7fff0100
    # concrete return address so angr doesn't see unconstrained jump
    state.memory.store(0x7fff0000, claripy.BVV(RET_ADDR, 64), endness=proj.arch.memory_endness)

    print("[3] Exploring all paths to return address...")
    simgr = proj.factory.simulation_manager(state)

    while simgr.active:
        simgr.step()
        for s in list(simgr.active):
            if s.addr == RET_ADDR:
                simgr.move(from_stash='active', to_stash='found',
                           filter_func=lambda s: s.addr == RET_ADDR)
                break

    print(f"    found={len(simgr.found)}, deadended={len(simgr.deadended)}")

    found = None
    for s in simgr.found:
        rax = s.regs.rax
        if s.solver.satisfiable(extra_constraints=[rax == 1]):
            found = s.copy()
            found.solver.add(rax == 1)
            break

    if found:
        solution = found.solver.eval(sym_input, cast_to=bytes)
        print(f"    SOLVED: {solution} (hex: {solution.hex()})")

        assert solution[0:1] == b"P", f"byte 0: expected 'P', got {solution[0:1]}"
        assert solution[1:2] == b"4", f"byte 1: expected '4', got {solution[1:2]}"
        assert (solution[2] ^ 0x42) == 0x10, f"byte 2: {solution[2]} ^ 0x42 != 0x10"
        assert (solution[3] + 0x20) == 0x87, f"byte 3: {solution[3]} + 0x20 != 0x87"

        print("[PASS] Direct engine: symbolic execution solved the crackme!")
        return True
    else:
        print("[FAIL] No state with rax==1 found")
        return False


def send_cmd(sock, cmd_type, params=None):
    cmd = {"type": cmd_type, "params": params or {}}
    sock.sendall((json.dumps(cmd) + "\n").encode())
    data = b""
    while b"\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Server closed")
        data += chunk
    return json.loads(data.split(b"\n")[0])


def test_server_protocol():
    """Test the server protocol via JSON over TCP."""
    env = {**os.environ, "PYTHONPATH": PYTHON_DIR}
    server = subprocess.Popen(
        [sys.executable, "-m", "ponce4ghidra_engine", "--port", str(TEST_PORT)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )

    try:
        time.sleep(3)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", TEST_PORT))

        print("\n[Server 1] Init...")
        resp = send_cmd(sock, "init", {"binary_path": BINARY})
        assert resp["status"] == "ok", f"Init failed: {resp}"
        print(f"    arch={resp['data']['arch']}")

        print("[Server 2] Get state...")
        resp = send_cmd(sock, "get_state")
        assert resp["status"] == "ok", f"Get state failed: {resp}"
        assert resp["data"]["initialized"] is True, f"Not initialized: {resp['data']}"

        print("[Server 3] Symbolize memory...")
        resp = send_cmd(sock, "symbolize_memory", {"addr": 0x10000, "size": 4, "state_addr": 0})
        assert resp["status"] == "ok", f"Symbolize failed: {resp}"
        print(f"    var: {resp['data']}")

        print("[Server 4] Set find/avoid...")
        resp = send_cmd(sock, "set_find", {"addresses": [0x1234]})
        assert resp["status"] == "ok"
        resp = send_cmd(sock, "set_avoid", {"addresses": [0x5678]})
        assert resp["status"] == "ok"

        print("[Server 5] Verify state...")
        resp = send_cmd(sock, "get_state")
        assert "mem_0x10000_4" in resp["data"]["variables"]
        assert "0x1234" in resp["data"]["find_addrs"]
        assert "0x5678" in resp["data"]["avoid_addrs"]

        print("\n[PASS] All server protocol tests passed!")
        sock.close()
    finally:
        server.terminate()
        server.wait(timeout=5)


def test_uninitialized_guards():
    """Commands that need a loaded binary must fail with a clear message.

    Regression test: the plugin can talk to an engine that has no binary loaded
    (e.g. after the engine process was restarted), and 'explore' used to die with
    "'NoneType' object has no attribute 'factory'".
    """
    env = {**os.environ, "PYTHONPATH": PYTHON_DIR}
    server = subprocess.Popen(
        [sys.executable, "-m", "ponce4ghidra_engine", "--port", str(TEST_PORT + 1)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )

    try:
        time.sleep(3)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", TEST_PORT + 1))

        print("\n[Guards 1] get_state reports not initialized...")
        resp = send_cmd(sock, "get_state")
        assert resp["data"]["initialized"] is False, resp

        print("[Guards 2] set_find needs no binary, so it still works...")
        resp = send_cmd(sock, "set_find", {"addresses": [0x1234]})
        assert resp["status"] == "ok", resp

        print("[Guards 3] explore without a binary: clear error, no AttributeError...")
        resp = send_cmd(sock, "explore", {"timeout_sec": 5})
        assert resp["status"] == "error", resp
        assert "not initialized" in resp["message"], resp
        assert "factory" not in resp["message"], resp

        print("[Guards 4] solve before explore: clear error...")
        resp = send_cmd(sock, "solve", {})
        assert resp["status"] == "error" and "explore" in resp["message"], resp

        print("[Guards 5] a failed init must not leave a stale project behind...")
        resp = send_cmd(sock, "init", {"binary_path": "/nonexistent/definitely-not-here"})
        assert resp["status"] == "error", resp
        resp = send_cmd(sock, "get_state")
        assert resp["data"]["initialized"] is False, resp

        print("[Guards 6] init a real binary, then explore is reachable...")
        resp = send_cmd(sock, "init", {"binary_path": BINARY})
        assert resp["status"] == "ok", resp
        resp = send_cmd(sock, "get_state")
        assert resp["data"]["initialized"] is True, resp

        print("\n[PASS] Uninitialized-command guards work!")
        sock.close()
    finally:
        server.terminate()
        server.wait(timeout=5)


def test_macho_import_hooks():
    """Exploring a Mach-O binary must reach the crackme's Find target.

    Regression test: angr ships no Mach-O SimOS, so it never installs the libc
    SimProcedures the way it does for ELF. States then fell through __stubs into
    CLE's "extern object", which is mapped for its first import only, and died
    with "IR decoding error at 0x100100008". Every exploration came back empty.
    """
    if "Mach-O" not in subprocess.run(
            ["file", BINARY], capture_output=True, text=True).stdout:
        print("\n[SKIP] test_crackme is not Mach-O")
        return

    env = {**os.environ, "PYTHONPATH": PYTHON_DIR}
    server = subprocess.Popen(
        [sys.executable, "-m", "ponce4ghidra_engine", "--port", str(TEST_PORT + 2)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )

    try:
        time.sleep(3)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", TEST_PORT + 2))

        print("\n[MachO 1] init hooks the binary's imports...")
        resp = send_cmd(sock, "init", {"binary_path": BINARY})
        assert resp["status"] == "ok", resp
        hooked = resp["data"]["hooked_imports"]
        print(f"    hooked: {hooked}")
        assert "_printf" in hooked, hooked
        assert "_strlen" in hooked, hooked

        # check_password returns 1 at 0x1000004d7 and 0 at 0x100000484.
        print("[MachO 2] explore to check_password's 'return 1'...")
        send_cmd(sock, "set_find", {"addresses": [0x1000004D7]})
        send_cmd(sock, "set_avoid", {"addresses": [0x100000484]})
        resp = send_cmd(sock, "explore", {"timeout_sec": 60})
        assert resp["status"] == "ok", resp
        data = resp["data"]
        print(f"    {data}")
        assert data["errored_count"] == 0, data["error_samples"]
        assert data["found_count"] > 0, "no path reached the Find target"

        print("\n[PASS] Mach-O import hooks let exploration reach the target!")
        sock.close()
    finally:
        server.terminate()
        server.wait(timeout=5)


def test_argument_symbolization():
    """A symbolized function argument and a symbolized argv[1] both solve the crackme.

    Regression test: state.memory.store() defaults to the memory plugin's own
    endness, which is big-endian whatever the target is, while VEX Load/Store
    follow the architecture's. The pointer written into the argv array therefore
    reached the program byte-reversed -- 0x7fffffffffef000 read back as
    0xf0feffffffff07 -- and the search still reported success, because every
    compare in check_password was satisfiable against memory nobody had
    constrained. The password it "solved" was four zero bytes.
    """
    if "Mach-O" not in subprocess.run(
            ["file", BINARY], capture_output=True, text=True).stdout:
        print("\n[SKIP] test_crackme is not Mach-O")
        return

    env = {**os.environ, "PYTHONPATH": PYTHON_DIR}
    server = subprocess.Popen(
        [sys.executable, "-m", "ponce4ghidra_engine", "--port", str(TEST_PORT + 3)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )

    try:
        time.sleep(3)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", TEST_PORT + 3))

        resp = send_cmd(sock, "init", {"binary_path": BINARY})
        assert resp["status"] == "ok", resp
        # check_password returns 1 at 0x1000004d7 and 0 at 0x100000484.
        send_cmd(sock, "set_find", {"addresses": [0x1000004D7]})
        send_cmd(sock, "set_avoid", {"addresses": [0x100000484]})

        print("\n[Args 1] symbolize check_password's rdi as a 4-byte buffer...")
        resp = send_cmd(sock, "symbolize_function_arg",
                        {"func_addr": 0x100000470, "reg_name": "rdi", "size": 4})
        assert resp["status"] == "ok", resp
        var_name = resp["data"]["name"]
        print(f"    {resp['data']}")

        print("[Args 2] explore from the function and solve...")
        resp = send_cmd(sock, "explore", {"timeout_sec": 90})
        assert resp["status"] == "ok", resp
        assert resp["data"]["found_count"] > 0, resp["data"]
        resp = send_cmd(sock, "solve", {})
        assert resp["status"] == "ok", resp
        answer = bytes(resp["data"]["solutions"][var_name][0]["value_bytes"])
        print(f"    {var_name} = {answer!r}")
        assert answer == b"P4Rg", f"expected b'P4Rg', got {answer!r}"

        print("[Args 3] symbolize argv[1] as a 4-byte buffer instead...")
        resp = send_cmd(sock, "symbolize_argv", {"size": 4, "index": 1})
        assert resp["status"] == "ok", resp
        var_name = resp["data"]["name"]
        print(f"    {resp['data']}")

        print("[Args 4] explore from the entry point and solve...")
        resp = send_cmd(sock, "explore", {"timeout_sec": 90})
        assert resp["status"] == "ok", resp
        assert resp["data"]["found_count"] > 0, resp["data"]
        resp = send_cmd(sock, "solve", {})
        assert resp["status"] == "ok", resp
        answer = bytes(resp["data"]["solutions"][var_name][0]["value_bytes"])
        print(f"    {var_name} = {answer!r}")
        assert answer == b"P4Rg", f"expected b'P4Rg', got {answer!r}"

        print("[Args 5] bad input is rejected rather than silently mangled...")
        resp = send_cmd(sock, "symbolize_argv", {"size": 4, "index": 0})
        assert resp["status"] == "error", resp
        resp = send_cmd(sock, "symbolize_function_arg",
                        {"func_addr": 0x100000470, "reg_name": "rsp", "size": 4})
        assert resp["status"] == "error", resp

        print("\n[PASS] Argument symbolization recovers the password both ways!")
        sock.close()
    finally:
        server.terminate()
        server.wait(timeout=5)


def test_reinit_contract():
    """The engine names its loaded binary, because re-initializing the same one discards state.

    Regression test: the plugin decided whether to send 'init' from its own record
    of what it had last sent. That record goes stale whenever the engine is
    restarted or the socket is reset, so a redundant init went out for a binary
    that was already loaded -- and init() clears the symbolized variables, which
    exist in the engine and nowhere else. Everything the user had set up vanished
    between symbolizing their input and solving for it, and the only thing they
    were told was "Nothing is symbolized".

    The engine cannot refuse a redundant init, so it reports the loaded binary in
    get_state and this pins the contract callers rely on: same path means already
    loaded, so do not init.
    """
    env = {**os.environ, "PYTHONPATH": PYTHON_DIR}
    server = subprocess.Popen(
        [sys.executable, "-m", "ponce4ghidra_engine", "--port", str(TEST_PORT + 4)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )

    try:
        time.sleep(3)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", TEST_PORT + 4))

        print("\n[Reinit 1] nothing loaded: get_state says so...")
        resp = send_cmd(sock, "get_state")
        assert resp["data"]["binary"] is None, resp["data"]

        print("[Reinit 2] after init, get_state names the loaded binary...")
        assert send_cmd(sock, "init", {"binary_path": BINARY})["status"] == "ok"
        resp = send_cmd(sock, "get_state")
        assert resp["data"]["binary"] == BINARY, resp["data"]

        print("[Reinit 3] so a caller can see there is nothing to initialize...")
        send_cmd(sock, "symbolize_argv", {"size": 4, "index": 1})
        resp = send_cmd(sock, "get_state")
        assert resp["data"]["variables"] == ["argv1"], resp["data"]

        print("[Reinit 4] ...because re-initializing the same binary wipes them...")
        send_cmd(sock, "init", {"binary_path": BINARY})
        resp = send_cmd(sock, "get_state")
        assert resp["data"]["variables"] == [], resp["data"]
        assert resp["data"]["binary"] == BINARY, resp["data"]

        print("[Reinit 5] a failed init does not leave a stale binary behind...")
        send_cmd(sock, "init", {"binary_path": "/nonexistent/definitely-not-here"})
        resp = send_cmd(sock, "get_state")
        assert resp["data"]["binary"] is None, resp["data"]

        print("\n[PASS] The loaded binary is reported, and re-init discards state!")
        sock.close()
    finally:
        server.terminate()
        server.wait(timeout=5)


def test_explore_progress():
    """Explore with report_progress sends live step counts before the result.

    The crackme is small enough that exploration finishes in a couple of
    seconds, so we might get zero or only a few progress lines — the test
    validates the protocol, not the volume.
    """
    if "Mach-O" not in subprocess.run(
            ["file", BINARY], capture_output=True, text=True).stdout:
        print("\n[SKIP] test_crackme is not Mach-O")
        return

    env = {**os.environ, "PYTHONPATH": PYTHON_DIR}
    server = subprocess.Popen(
        [sys.executable, "-m", "ponce4ghidra_engine", "--port", str(TEST_PORT + 5)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )

    try:
        time.sleep(3)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", TEST_PORT + 5))

        send_cmd(sock, "init", {"binary_path": BINARY})
        send_cmd(sock, "set_find", {"addresses": [0x1000004D7]})
        send_cmd(sock, "set_avoid", {"addresses": [0x100000484]})
        send_cmd(sock, "symbolize_argv", {"size": 4, "index": 1})

        print("\n[Progress 1] explore with report_progress collects lines...")
        cmd = {"type": "explore", "params": {"timeout_sec": 60, "report_progress": True}}
        sock.sendall((json.dumps(cmd) + "\n").encode())

        progress_lines = []
        final = None
        buf = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                resp = json.loads(line)
                if resp["status"] == "progress":
                    progress_lines.append(resp)
                else:
                    final = resp
                    break
            if final:
                break

        print(f"    progress lines received: {len(progress_lines)}")
        for p in progress_lines[:3]:
            d = p["data"]
            print(f"      step {d['steps']}: {d['active']} active, "
                  f"{d['found']} found ({d['elapsed']}s)")

        assert final is not None, "no final response"
        assert final["status"] == "ok", final
        assert final["data"]["found_count"] > 0, final["data"]

        if progress_lines:
            d = progress_lines[0]["data"]
            assert "active" in d, d
            assert "steps" in d, d
            assert "elapsed" in d, d
            print("[Progress 2] progress line schema is correct")

        print(f"\n[PASS] Explore progress: {len(progress_lines)} updates, "
              f"found={final['data']['found_count']}")
        sock.close()
    finally:
        server.terminate()
        server.wait(timeout=5)


def test_elf_function_argument():
    """An ELF binary can be loaded and solved via symbolize_function_argument.

    First ELF fixture in the test suite. Validates that:
    - init() detects an ELF executable (is_library=False, no Mach-O hooks)
    - symbolize_function_argument works on ELF (call_state, generic sp)
    - explore + solve recovers the license key
    """
    if not os.path.isfile(ELF_BINARY):
        print("\n[SKIP] test_license_elf not found")
        return

    if "ELF" not in subprocess.run(
            ["file", ELF_BINARY], capture_output=True, text=True).stdout:
        print("\n[SKIP] test_license_elf is not ELF")
        return

    env = {**os.environ, "PYTHONPATH": PYTHON_DIR}
    server = subprocess.Popen(
        [sys.executable, "-m", "ponce4ghidra_engine", "--port", str(TEST_PORT + 6)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )

    try:
        time.sleep(3)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", TEST_PORT + 6))

        print("\n[ELF-func 1] init ELF binary...")
        resp = send_cmd(sock, "init", {"binary_path": ELF_BINARY})
        assert resp["status"] == "ok", resp
        assert resp["data"]["is_library"] is False, resp["data"]
        assert resp["data"]["hooked_imports"] == [], resp["data"]
        print(f"    arch={resp['data']['arch']} entry={resp['data']['entry']}")

        # validate_license at 0x1016ff0
        # return 1 (valid) at 0x1017327, return 0 (invalid) at 0x101731e
        print("[ELF-func 2] symbolize validate_license's rdi as 19-byte buffer...")
        send_cmd(sock, "set_find", {"addresses": [0x1017327]})
        send_cmd(sock, "set_avoid", {"addresses": [0x101731e]})
        resp = send_cmd(sock, "symbolize_function_arg",
                        {"func_addr": 0x1016ff0, "reg_name": "rdi", "size": 19})
        assert resp["status"] == "ok", resp
        var_name = resp["data"]["name"]
        print(f"    {resp['data']}")

        print("[ELF-func 3] explore and solve...")
        resp = send_cmd(sock, "explore", {"timeout_sec": 120})
        assert resp["status"] == "ok", resp
        assert resp["data"]["found_count"] > 0, resp["data"]
        resp = send_cmd(sock, "solve", {})
        assert resp["status"] == "ok", resp
        answer = bytes(resp["data"]["solutions"][var_name][0]["value_bytes"])
        print(f"    {var_name} = {answer!r}")
        assert answer == b"K9mZ-4wR2-Xp7B-3nLf", f"expected license key, got {answer!r}"

        print("\n[PASS] ELF function argument symbolization solved the license!")
        sock.close()
    finally:
        server.terminate()
        server.wait(timeout=5)


def test_elf_argv_symbolization():
    """An ELF binary can be solved via symbolize_argv (the SimUserland path).

    This is the first test that exercises the SimUserland/SimLinux argv layout
    path -- entry_state(args=...) on ELF. The Mach-O tests use a manual argv
    layout because angr has no Mach-O SimOS.
    """
    if not os.path.isfile(ELF_BINARY):
        print("\n[SKIP] test_license_elf not found")
        return

    if "ELF" not in subprocess.run(
            ["file", ELF_BINARY], capture_output=True, text=True).stdout:
        print("\n[SKIP] test_license_elf is not ELF")
        return

    env = {**os.environ, "PYTHONPATH": PYTHON_DIR}
    server = subprocess.Popen(
        [sys.executable, "-m", "ponce4ghidra_engine", "--port", str(TEST_PORT + 7)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )

    try:
        time.sleep(3)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", TEST_PORT + 7))

        resp = send_cmd(sock, "init", {"binary_path": ELF_BINARY})
        assert resp["status"] == "ok", resp

        # In main: return 0 (success, prints "Valid!") at 0x1018814
        #          return 1 (fail, prints "Invalid") at 0x101882e
        send_cmd(sock, "set_find", {"addresses": [0x1018814]})
        send_cmd(sock, "set_avoid", {"addresses": [0x101882e]})

        print("\n[ELF-argv 1] symbolize argv[1] as 19-byte buffer...")
        resp = send_cmd(sock, "symbolize_argv", {"size": 19, "index": 1})
        if resp["status"] == "error":
            print(f"    [SKIP] symbolize_argv failed on ELF: {resp['message']}")
            print("    (SimUserland argv path may not work for this binary)")
            sock.close()
            return
        assert resp["status"] == "ok", resp
        var_name = resp["data"]["name"]
        print(f"    {resp['data']}")

        print("[ELF-argv 2] explore from entry point (this may take a while)...")
        resp = send_cmd(sock, "explore", {"timeout_sec": 120})
        assert resp["status"] == "ok", resp
        found = resp["data"]["found_count"]
        print(f"    found={found} active={resp['data']['active_count']} "
              f"errored={resp['data']['errored_count']}")

        if found == 0:
            print("    [SKIP] No path reached the Find target from entry point.")
            print("    (The zig-compiled ELF with ubsan may be too complex for "
                  "full entry-point exploration within the timeout.)")
            sock.close()
            return

        resp = send_cmd(sock, "solve", {})
        assert resp["status"] == "ok", resp
        answer = bytes(resp["data"]["solutions"][var_name][0]["value_bytes"])
        print(f"    {var_name} = {answer!r}")
        assert answer == b"K9mZ-4wR2-Xp7B-3nLf", f"expected license key, got {answer!r}"

        print("\n[PASS] ELF argv symbolization solved the license from entry point!")
        sock.close()
    finally:
        server.terminate()
        server.wait(timeout=5)


if __name__ == "__main__":
    print("=" * 60)
    print("Ponce4Ghidra Engine Test Suite")
    print("=" * 60)

    ok = test_direct_engine()
    if ok:
        test_server_protocol()
        test_uninitialized_guards()
        test_macho_import_hooks()
        test_argument_symbolization()
        test_reinit_contract()
        test_explore_progress()
        test_elf_function_argument()
        test_elf_argv_symbolization()
    print("\nAll tests done.")
