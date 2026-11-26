"""Q-SHIELD comparative X25519 vs ML-KEM benchmark engine.

Measurements are local-provider microbenchmarks, not network/protocol latency.
X25519 performs key agreement (not KEM encapsulation/decapsulation).
ML-KEM operations follow the installed cryptography provider implementation.
"""
import json
import statistics
import time
from uuid import uuid4

from flask import Blueprint, current_app, jsonify, request
from cryptography.hazmat.primitives.asymmetric import x25519, mlkem

from database.db import get_db_connection

benchmark_bp = Blueprint("benchmarking", __name__)

ALGORITHMS = {
    "X25519": {
        "kind": "key_agreement",
        "operations": ("key_generation", "key_agreement"),
    },
    "ML-KEM-512": {
        "kind": "kem",
        "operations": ("key_generation", "encapsulation", "decapsulation"),
    },
    "ML-KEM-768": {
        "kind": "kem",
        "operations": ("key_generation", "encapsulation", "decapsulation"),
    },
    "ML-KEM-1024": {
        "kind": "kem",
        "operations": ("key_generation", "encapsulation", "decapsulation"),
    },
}
# Resolve provider classes dynamically. cryptography releases/providers may expose
# only a subset of the FIPS 203 parameter sets. Never fail module import merely
# because an optional parameter set is unavailable.
_KEM_CLASS_NAMES = {
    "ML-KEM-512": "MLKEM512PrivateKey",
    "ML-KEM-768": "MLKEM768PrivateKey",
    "ML-KEM-1024": "MLKEM1024PrivateKey",
}
KEM_CLASSES = {
    name: getattr(mlkem, class_name)
    for name, class_name in _KEM_CLASS_NAMES.items()
    if hasattr(mlkem, class_name)
}

SUPPORTED_ALGORITHMS = ["X25519", *KEM_CLASSES.keys()]
UNAVAILABLE_ALGORITHMS = [
    name for name in _KEM_CLASS_NAMES if name not in KEM_CLASSES
]
MAX_REPETITIONS = 1000
MAX_WARMUPS = 20


def _measure_ms(operation):
    started = time.perf_counter_ns()
    result = operation()
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    return result, elapsed_ms


def _percentile(values, percentile):
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * percentile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def _summary(values):
    return {
        "samples": len(values),
        "mean_ms": round(statistics.fmean(values), 6),
        "median_ms": round(statistics.median(values), 6),
        "stdev_ms": round(statistics.stdev(values), 6) if len(values) > 1 else 0.0,
        "p95_ms": round(_percentile(values, 0.95), 6),
        "min_ms": round(min(values), 6),
        "max_ms": round(max(values), 6),
        "raw_ms": [round(value, 6) for value in values],
    }


def _public_bytes_x25519(public_key):
    from cryptography.hazmat.primitives import serialization
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _benchmark_x25519(repetitions, warmups):
    timings = {"key_generation": [], "key_agreement": []}
    # Warm-up is excluded from reported samples.
    for _ in range(warmups):
        private = x25519.X25519PrivateKey.generate()
        peer = x25519.X25519PrivateKey.generate()
        private.exchange(peer.public_key())
    for _ in range(repetitions):
        private, elapsed = _measure_ms(x25519.X25519PrivateKey.generate)
        timings["key_generation"].append(elapsed)
        peer = x25519.X25519PrivateKey.generate()
        shared, elapsed = _measure_ms(lambda: private.exchange(peer.public_key()))
        if len(shared) != 32:
            raise RuntimeError("X25519 produced an unexpected shared-secret size.")
        timings["key_agreement"].append(elapsed)
    return {
        "algorithm": "X25519",
        "family": "classical",
        "operation_model": "Key generation and Diffie-Hellman key agreement; not a KEM.",
        "sizes_bytes": {
            "public_key": 32,
            "shared_secret": 32,
            "ciphertext": None,
        },
        "operations": {name: _summary(values) for name, values in timings.items()},
    }


def _benchmark_kem(name, repetitions, warmups):
    key_class = KEM_CLASSES[name]
    timings = {
        "key_generation": [],
        "encapsulation": [],
        "decapsulation": [],
    }
    # Warm-up exercises all three provider operations without recording them.
    for _ in range(warmups):
        private = key_class.generate()
        shared_secret, ciphertext = private.public_key().encapsulate()
        recovered = private.decapsulate(ciphertext)
        if shared_secret != recovered:
            raise RuntimeError(f"{name} warm-up round-trip failed.")
    public_key_size = ciphertext_size = secret_size = None
    for _ in range(repetitions):
        private, elapsed = _measure_ms(key_class.generate)
        timings["key_generation"].append(elapsed)
        public_key = private.public_key()
        # Encapsulation and decapsulation are timed independently.
        (shared_secret, ciphertext), elapsed = _measure_ms(public_key.encapsulate)
        timings["encapsulation"].append(elapsed)
        recovered, elapsed = _measure_ms(lambda: private.decapsulate(ciphertext))
        timings["decapsulation"].append(elapsed)
        if shared_secret != recovered:
            raise RuntimeError(f"{name} encapsulation/decapsulation mismatch.")
        public_key_size = len(public_key.public_bytes_raw())
        ciphertext_size = len(ciphertext)
        secret_size = len(shared_secret)
    return {
        "algorithm": name,
        "family": "post_quantum",
        "standard": "NIST FIPS 203",
        "operation_model": "KEM key generation, encapsulation and decapsulation.",
        "sizes_bytes": {
            "public_key": public_key_size,
            "ciphertext": ciphertext_size,
            "shared_secret": secret_size,
        },
        "operations": {operation: _summary(values) for operation, values in timings.items()},
    }


def run_comparative_benchmark(repetitions=30, warmups=2, algorithms=None):
    if isinstance(repetitions, bool) or not isinstance(repetitions, int):
        raise ValueError("repetitions must be an integer.")
    if not 3 <= repetitions <= MAX_REPETITIONS:
        raise ValueError(f"repetitions must be between 3 and {MAX_REPETITIONS}.")
    if isinstance(warmups, bool) or not isinstance(warmups, int):
        raise ValueError("warmups must be an integer.")
    if not 0 <= warmups <= MAX_WARMUPS:
        raise ValueError(f"warmups must be between 0 and {MAX_WARMUPS}.")
    # Default to algorithms actually exposed by the installed provider.
    selected = list(SUPPORTED_ALGORITHMS) if algorithms is None else algorithms
    if not isinstance(selected, list) or not selected:
        raise ValueError("algorithms must be a non-empty array.")
    if any(not isinstance(name, str) for name in selected):
        raise ValueError("Every algorithm name must be a string.")
    unknown = sorted(set(selected) - set(ALGORITHMS))
    if unknown:
        raise ValueError("Unknown algorithms: " + ", ".join(unknown))
    unavailable = sorted(set(selected) - set(SUPPORTED_ALGORITHMS))
    if unavailable:
        raise ValueError(
            "Algorithms unavailable in the installed cryptography provider: "
            + ", ".join(unavailable)
            + ". Available algorithms: "
            + ", ".join(SUPPORTED_ALGORITHMS)
        )
    if len(set(selected)) != len(selected):
        raise ValueError("algorithms must not contain duplicates.")

    results = []
    for name in selected:
        if name == "X25519":
            results.append(_benchmark_x25519(repetitions, warmups))
        else:
            results.append(_benchmark_kem(name, repetitions, warmups))
    return {
        "benchmark_id": str(uuid4()),
        "methodology": {
            "repetitions": repetitions,
            "warmups": warmups,
            "timer": "time.perf_counter_ns; reported in milliseconds",
            "statistics": ["mean", "median", "standard deviation", "p95", "min", "max"],
            "notes": [
                "Local cryptographic-provider microbenchmark; excludes network, serialization and application overhead.",
                "Warm-up samples are excluded from reported statistics.",
                "X25519 key agreement is not a KEM and has no encapsulation or decapsulation operation.",
                "Results depend on CPU, operating system, cryptography provider, build and system load.",
                "Do not interpret a single run as a universal algorithm ranking.",
            ],
        },
        "results": results,
    }


def _persist_run(report):
    connection = get_db_connection()
    try:
        connection.execute(
            """INSERT INTO comparative_benchmark_runs
               (benchmark_id, repetitions, warmups, report_json)
               VALUES (?, ?, ?, ?)""",
            (
                report["benchmark_id"],
                report["methodology"]["repetitions"],
                report["methodology"]["warmups"],
                json.dumps(report, separators=(",", ":")),
            ),
        )
        connection.commit()
    finally:
        connection.close()


@benchmark_bp.route("/api/benchmarks/catalog", methods=["GET"])
def benchmark_catalog():
    return jsonify({
        "supported_algorithms": SUPPORTED_ALGORITHMS,
        "unavailable_algorithms": UNAVAILABLE_ALGORITHMS,
        "algorithm_details": {
            "X25519": {
                "family": "classical",
                "operations": ["key_generation", "key_agreement"],
                "standard": "RFC 7748",
            },
            **{
                name: {
                    "family": "post_quantum",
                    "operations": ["key_generation", "encapsulation", "decapsulation"],
                    "standard": "NIST FIPS 203",
                }
                for name in KEM_CLASSES
            },
        },
        "provider": "cryptography",
    }), 200


@benchmark_bp.route("/api/benchmarks/run", methods=["POST"])
def create_benchmark():
    data = request.get_json(silent=True) or {}
    try:
        report = run_comparative_benchmark(
            repetitions=data.get("repetitions", 30),
            warmups=data.get("warmups", 2),
            algorithms=data.get("algorithms"),
        )
        _persist_run(report)
        return jsonify({"message": "Comparative benchmark completed.", **report}), 201
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except Exception:
        current_app.logger.exception("Comparative benchmark failed")
        return jsonify({"error": "Comparative benchmark failed. Check provider compatibility and backend logs."}), 500


@benchmark_bp.route("/api/benchmarks/runs", methods=["GET"])
def list_benchmark_runs():
    connection = get_db_connection()
    try:
        rows = connection.execute(
            """SELECT benchmark_id, repetitions, warmups, created_at
               FROM comparative_benchmark_runs ORDER BY id DESC LIMIT 100"""
        ).fetchall()
        return jsonify({"total": len(rows), "runs": [dict(row) for row in rows]}), 200
    finally:
        connection.close()


@benchmark_bp.route("/api/benchmarks/runs/<benchmark_id>", methods=["GET"])
def get_benchmark_run(benchmark_id):
    connection = get_db_connection()
    try:
        row = connection.execute(
            "SELECT report_json FROM comparative_benchmark_runs WHERE benchmark_id = ?",
            (benchmark_id,),
        ).fetchone()
        if row is None:
            return jsonify({"error": "Benchmark run not found."}), 404
        return jsonify(json.loads(row["report_json"])), 200
    finally:
        connection.close()
