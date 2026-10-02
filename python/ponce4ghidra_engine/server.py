import argparse
import json
import logging
import socket
import sys
import threading
import traceback

from .engine import SymbolicEngine
from .engine_triton import TRITON_AVAILABLE, TritonEngine
from .protocol import Command, parse_command, ok, error, progress

HOST = "127.0.0.1"
PORT = 13370

logging.basicConfig(
    level=logging.INFO,
    format="[ponce4ghidra] %(levelname)s %(message)s",
)
logger = logging.getLogger("ponce4ghidra")

def _handle_solve(eng, p):
    var_name = p.get("var_name")
    if var_name:
        return eng.solve(var_name)
    return eng.solve_all(max_solutions=p.get("max_solutions", 1))

HANDLERS = {
    "init": lambda eng, p: eng.init(p["binary_path"]),
    "symbolize_register": lambda eng, p: eng.symbolize_register(p["reg_name"], p.get("state_addr", 0)),
    "symbolize_memory": lambda eng, p: eng.symbolize_memory(p["addr"], p["size"], p.get("state_addr", 0)),
    "symbolize_function_arg": lambda eng, p: eng.symbolize_function_argument(
        p["func_addr"], p.get("reg_name", "rdi"), p.get("size", 8), p.get("name")
    ),
    "symbolize_argv": lambda eng, p: eng.symbolize_argv(
        p.get("size", 8), p.get("index", 1), p.get("name")
    ),
    "set_find": lambda eng, p: eng.set_find(p["addresses"]),
    "set_avoid": lambda eng, p: eng.set_avoid(p["addresses"]),
    "explore": None,  # handled specially in handle_client for progress support
    "solve": _handle_solve,
    "get_state": lambda eng, p: eng.get_state(),
    "get_constraints": lambda eng, p: eng.get_constraints(
        p.get("stash", "found"), p.get("index", 0)
    ),
    "negate_branch": lambda eng, p: eng.negate_branch(p["branch_addr"]),
    "replay": lambda eng, p: eng.replay(p.get("log", [])),
}


def handle_client(conn: socket.socket, engine):
    with conn.makefile("r", encoding="utf-8") as reader, \
         conn.makefile("w", encoding="utf-8") as writer:
        for line in reader:
            line = line.strip()
            if not line:
                continue
            try:
                cmd = parse_command(line)
                logger.info("CMD: %s %s", cmd.type, cmd.params)
                if cmd.type == "explore":
                    cb = None
                    if cmd.params.get("report_progress", False):
                        def cb(data):
                            writer.write(progress(data).to_json() + "\n")
                            writer.flush()
                    result = engine.explore(
                        cmd.params.get("timeout_sec", 60),
                        progress_callback=cb,
                        use_veritesting=cmd.params.get("veritesting", False),
                        use_unicorn=cmd.params.get("unicorn", False),
                    )
                    resp = ok(result)
                else:
                    handler = HANDLERS.get(cmd.type)
                    if handler is None:
                        resp = error(f"Unknown command: {cmd.type}")
                    else:
                        result = handler(engine, cmd.params)
                        resp = ok(result)
            except Exception as e:
                logger.exception("Error handling command")
                resp = error(str(e))

            writer.write(resp.to_json() + "\n")
            writer.flush()


def _create_engine(name: str):
    if name == "triton":
        if not TRITON_AVAILABLE:
            logger.warning(
                "Triton backend requested but not installed. "
                "Install with: pip install triton-library lief. "
                "Falling back to angr."
            )
            return SymbolicEngine()
        logger.info("Using Triton concolic execution backend")
        return TritonEngine()
    logger.info("Using angr symbolic execution backend")
    return SymbolicEngine()


def main():
    parser = argparse.ArgumentParser(description="Ponce4Ghidra symbolic execution engine")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--engine", choices=["angr", "triton"], default="angr",
                        help="Execution backend (default: angr)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger("ponce4ghidra").setLevel(logging.DEBUG)

    engine = _create_engine(args.engine)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(1)
    logger.info("Ponce4Ghidra engine listening on %s:%d", args.host, args.port)

    try:
        while True:
            conn, addr = server.accept()
            logger.info("Client connected from %s", addr)
            thread = threading.Thread(
                target=handle_client, args=(conn, engine), daemon=True
            )
            thread.start()
    except KeyboardInterrupt:
        logger.info("Shutting down")
    finally:
        server.close()


if __name__ == "__main__":
    main()
