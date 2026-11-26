# Q-SHIELD comparative benchmark provider compatibility fix

Replace `backend/benchmarking/engine.py` with the included file.

The previous version directly referenced MLKEM512PrivateKey at import time.
The installed cryptography provider does not expose that class, so importing
the module failed before Flask could start. This version resolves supported
parameter-set classes dynamically, defaults to provider-supported algorithms,
and returns an explicit error if an unavailable set is requested.

New endpoint:
- GET /api/benchmarks/catalog

Use the catalog to determine which algorithms the installed provider supports.
Do not represent unavailable parameter sets with invented measurements.
