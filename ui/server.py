#!/usr/bin/env python3
"""Clangover Attack Visualizer - SSE backend."""

import json
import os
import signal
import subprocess
import sys
import time

from flask import Flask, Response, jsonify, request, send_file

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, "attack_log.jsonl")

TARGETS = {
    "pqcrystals": {
        "binary": os.path.join(BASE_DIR, "clangover-pqcrystal-kyber-ui"),
        "make_target": "attack-pqcrystal-kyber",
        "label": "PQ-Crystals Kyber (b628ba7)",
    },
    "liboqs": {
        "binary": os.path.join(BASE_DIR, "clangover-liboqs-ui"),
        "make_target": "attack-liboqs",
        "label": "LibOQS v0.10.0",
    },
}

process = None
paused = False
active_target = None


@app.route("/")
def index():
    return send_file("index.html")


@app.route("/learn")
def learn():
    return send_file("learn.html")


@app.route("/api/status")
def status():
    global process, paused
    if process is None:
        if os.path.exists(LOG_FILE):
            return jsonify({"state": "finished", "pid": None, "target": active_target})
        return jsonify({"state": "idle", "pid": None, "target": active_target})

    if process.poll() is not None:
        return jsonify({"state": "finished", "pid": None, "target": active_target})

    if paused:
        return jsonify({"state": "paused", "pid": process.pid, "target": active_target})

    return jsonify({"state": "running", "pid": process.pid, "target": active_target})


def _ensure_binary(target_key):
    """Build the UI variant if needed."""
    t = TARGETS[target_key]
    if not os.path.exists(t["binary"]):
        result = subprocess.run(
            ["make", t["make_target"]], cwd=BASE_DIR, capture_output=True, text=True
        )
        if result.returncode != 0:
            return result.stderr
    return None


def _spawn_process(target_key):
    """Spawn a new attack process."""
    global process, paused, active_target
    t = TARGETS[target_key]
    process = subprocess.Popen(
        [t["binary"]],
        cwd=BASE_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    paused = False
    active_target = target_key


@app.route("/api/start", methods=["POST"])
def start():
    global process, paused

    target_key = request.args.get("target", "pqcrystals")
    if target_key not in TARGETS:
        return jsonify({"error": f"Unknown target: {target_key}"}), 400

    # Resume if paused
    if process and process.poll() is None and paused:
        process.send_signal(signal.SIGCONT)
        paused = False
        return jsonify({"status": "resumed", "pid": process.pid, "target": active_target})

    # Already running
    if process and process.poll() is None:
        return jsonify({"error": "Attack already running"}), 400

    # Fresh start
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)

    err = _ensure_binary(target_key)
    if err:
        return jsonify({"error": "Build failed", "details": err}), 500

    _spawn_process(target_key)
    return jsonify({"status": "started", "pid": process.pid, "target": active_target})


@app.route("/api/stop", methods=["POST"])
def stop():
    global process, paused
    if process and process.poll() is None:
        process.send_signal(signal.SIGSTOP)
        paused = True
        return jsonify({"status": "paused", "pid": process.pid, "target": active_target})
    return jsonify({"status": "not_running"})


@app.route("/api/restart", methods=["POST"])
def restart():
    global process, paused

    target_key = request.args.get("target", active_target or "pqcrystals")
    if target_key not in TARGETS:
        return jsonify({"error": f"Unknown target: {target_key}"}), 400

    # Kill existing process
    if process and process.poll() is None:
        if paused:
            try:
                process.send_signal(signal.SIGCONT)
            except OSError:
                pass
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
    process = None
    paused = False

    # Remove log
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)

    err = _ensure_binary(target_key)
    if err:
        return jsonify({"error": "Build failed", "details": err}), 500

    _spawn_process(target_key)
    return jsonify({"status": "restarted", "pid": process.pid, "target": active_target})


def _generate_stream(replay=False):
    """SSE generator. If replay=True, replay existing log then live-tail."""
    waited = 0
    while not os.path.exists(LOG_FILE):
        time.sleep(0.1)
        waited += 0.1
        if waited > 10:
            yield 'data: {"event":"error","msg":"Log file not created"}\n\n'
            return

    with open(LOG_FILE, "r") as f:
        replaying = replay
        while True:
            line = f.readline()
            if line.strip():
                yield f"data: {line.strip()}\n\n"
            else:
                if replaying:
                    yield 'data: {"event":"replay_done"}\n\n'
                    replaying = False

                if process and process.poll() is not None:
                    for remaining in f:
                        if remaining.strip():
                            yield f"data: {remaining.strip()}\n\n"
                    yield 'data: {"event":"stream_end"}\n\n'
                    return
                if process is None:
                    yield 'data: {"event":"stream_end"}\n\n'
                    return
                time.sleep(0.05)


@app.route("/api/stream")
def stream():
    return Response(
        _generate_stream(replay=False),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/replay")
def replay():
    return Response(
        _generate_stream(replay=True),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    print(f"Clangover Visualizer running at http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
