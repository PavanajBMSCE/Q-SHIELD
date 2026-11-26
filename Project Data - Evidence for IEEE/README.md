# Q-SHIELD research evidence and software snapshot

Prepared from Q-SHIELD-main.zip and the supplied final manuscript. The original evidence was curated without rerunning experiments. New user-supplied reproduction runs dated 2026-11-26 are now included.

## Contents
- 01_control: exact comparison JSON, PDF, original evidence ZIP, embedded archives, and database comparison row. Both embedded archives hash to fd93df665a42daf3d2d8219393a6bc173876b368cc5257ad205dffc6f0c6f6ec. Run ID 2d029f0c-78ae-43ad-8b38-84799ff629e7.
- 02_pqc_migration: original and candidate PQC-migrated archive, extracted source and migration report, and newly derived source diff. The candidate archive's report links to the original hash; its own SHA-256 is 6616197020fe14bc29721786d3fb28bdc791ad9d1112de927eccc30cc820d207. This is not proof it was the exact archive used in the final screenshot experiment.
- 03_benchmarks: original JSON plus machine-readable raw timings (240 samples across eight operations, 30 each), summaries and key sizes. Three warmups excluded; hardware details unavailable.
- 04_audit: inventory report and earlier Module 7.10 audit evidence. The latter uses module710_sample.zip and is not the final screenshot audit.
- 05_historical_migration: earlier migration outputs, comparison reports and evidence; separate from the paper's main migration experiment. The archived comparison 4064dada-4069-4898-adec-59495f5abebf is conventional hardening (5 to 15, zero PQC detections), not the final 5-to-25 experiment. Older reports use different counting rules.
- 06_manuscript_figures: architecture and all 26 experimental images extracted directly from the supplied manuscript, with figure index. Author portraits excluded.
- 07_manuscript_tables: the four manuscript tables in CSV form.
- 08_software: project source, test fixtures, tests, dependency manifests and module notes. Runtime database, installers, caches, backup code and uploaded reports are not included in this source snapshot.
- MANIFEST.csv: SHA-256, size and provenance for each packaged file (excluding the manifest itself).

## Evidence boundary
The original screenshot run's exact JSON remains unavailable. However, the newly supplied migration reproduction (ID ebe0bc35-e554-4c40-966c-06162931ce09) matches the reported metrics: readiness 5 to 25, one resolved, 16 remaining, zero new, three PQC detections, eight conventional hardening adoptions. The new control (ID 45ecbe66-085e-4866-bb4e-744e2d1a1899) likewise matches the control metrics. Both runs contain JSON, PDF and original/migrated archives; migration also includes the source diff. All four embedded archive hashes were independently recomputed and match their respective JSON records. The migration reproduction uses the original hash fd93df665a42daf3d2d8219393a6bc173876b368cc5257ad205dffc6f0c6f6ec and migrated hash 524a82a1bd7b2f375878e1dd84a48a128490d82fed1b30b5118884befd4a95d8. This differs from the earlier candidate archive hash. Both new runs are stored separately in reproduction_2026-11-26 subfolders. They are fresh reproductions, not the historical screenshot run itself. Provider self-test was NOT_RUN, uploaded code was not executed, and no benchmark records were available in either new comparison. Archived provider benchmarks remain independent. Readiness is heuristic, not certification.

## Reproduction starting point
Use Python with a compatible cryptography release and Node.js. From 08_software/backend install requirements.txt in a virtual environment, then run python app.py. From 08_software/frontend run npm ci and npm run dev. The supplied tests are under backend/tests; run from backend with python -m unittest discover -s tests. These instructions have not been executed here. Use the provided demo archives in an isolated environment; they intentionally contain weak cryptography and dummy hardcoded credentials. The backend has a local-development secret default; configure a fresh SECRET_KEY if deploying.

## Sharing review
For an IEEE data deposit, use folders 01–07; software is separately grouped in 08. This ZIP is a curated evidence bundle, not a validated Code Ocean capsule. Obtain author approval and review source, reports and screenshots for confidential information before public release. No real credentials were established by the limited inspection; this is not a comprehensive secret audit. No license was found in the supplied source archive; confirm publication rights and licensing before release.
