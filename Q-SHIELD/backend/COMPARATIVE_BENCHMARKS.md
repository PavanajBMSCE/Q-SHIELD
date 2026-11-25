# Q-SHIELD Comparative Cryptographic Benchmark

## Endpoints
- `POST /api/benchmarks/run` — execute and persist a benchmark.
- `GET /api/benchmarks/runs` — list recent benchmark runs.
- `GET /api/benchmarks/runs/<benchmark_id>` — retrieve a complete result.

Example request:
```json
{"repetitions": 30, "warmups": 2, "algorithms": ["X25519", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]}
```
`algorithms` may be omitted to run all four algorithms. Repetitions must be 3–1000 and warmups 0–20.

## Methodology
Uses `time.perf_counter_ns()` and reports milliseconds. Warmups are excluded. Per-operation summaries include mean, median, standard deviation, p95, minimum, maximum and raw samples. KEM encapsulation and decapsulation are timed separately and their shared secrets are compared on every repetition. X25519 key agreement is measured as a Diffie-Hellman exchange; it is not described as KEM encapsulation or decapsulation.

Public-key, ciphertext and shared-secret sizes are reported where applicable. X25519 has no KEM ciphertext, so its ciphertext size is null.

## Interpretation
These are local provider microbenchmarks, not network or end-to-end application latency. Results depend on hardware, operating system, provider build, CPU load and repetition count. Use repeated runs on the same machine for comparisons. Do not use the result as a universal ranking or certification.

## Database
`database.initialize_database()` creates `comparative_benchmark_runs` without altering existing tables. Existing benchmark and migration history remains intact.
