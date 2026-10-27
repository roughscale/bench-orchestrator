# Changelog

## Unreleased — CAI integration

Work on the `feature/cai_integration` branch adding live Hack The Box (HTB)
challenge provisioning and real flag verification for the CAI agent. All
changes below are uncommitted at time of writing.

### Added

- **HTB Challenge target provider** (`src/bench_orchestrator/targets/htb_challenge.py`,
  wired in `targets/factory.py` as `htb_challenge`). Provisions a live HTB
  *Challenge* container instance (`play_methods: ["container"]`, e.g.
  Diagnostic) through the Labs v4 API, resolving its `host:port` at run time
  via HTB's Pusher/Echo websocket — no manual start/stop or address paste-in.
  Requires `HTB_API_KEY`.
- **Flag verification server** (`src/bench_orchestrator/agents/htb_flag_verify_server.py`).
  A local HTTP server the CAI container's `submit_flag` tool calls back into
  (`CHALLENGE_FLAG_VERIFY_URL`) so flags are checked against HTB's real
  `challenge/own` / `machine/own` endpoints live during the run, instead of a
  local shape/exact match. Degrades gracefully to the old behaviour when HTB
  verification can't be resolved.
- **`verified_flags` scorer** (`src/bench_orchestrator/scoring/verified_flags.py`,
  wired in `scoring/factory.py`). Trusts the agent's already-verified result
  rather than re-deriving or re-submitting flags, and just checks that the run
  reported the required number of flags.
- **HTB challenge file fetcher** (`tools/fetch_htb_challenge_files.py`).
  Downloads the file-based HTB Challenge/Sherlock artifacts referenced by the
  challenge manifests into their `source_dir` for `StaticHostTargetProvider`
  to mount.
- **CAI config** `configs/cai-sonnet-5.yaml` (claude-sonnet-5, redteam agent).
- **Eval sets** under `evals/` for running the remaining / retry HTB challenge
  batches.
- **Tests** for the CAI agent, HTB provider, HTB challenge provider, flag
  verify server, verified-flags scorer, and the challenge-file fetcher.

### Changed

- **CAI agent adapter** (`src/bench_orchestrator/agents/cai_agent.py`):
  - Mounts downloaded challenge files into the container (`/opt/cai/challenge`)
    for file-based challenges.
  - Starts/stops the flag verify server around the run and points the
    container at it.
  - Names the container (`cai-bench-<uuid>`) so a timeout can `docker kill` it
    directly.
  - Attaches CAI's own session transcript (`*.jsonl`) as artifacts on both
    success and failure, so scorers can recover flags CAI itself missed or
    mis-extracted.
- **HTB machine target provider** (`src/bench_orchestrator/targets/htb.py`):
  - Reads `isSingleFlag` from the machine profile to record how many flags are
    required (`required_flags`) instead of hardcoding it.
  - Reuses an already-active machine even while it is still booting, avoiding a
    403 from re-spawning.
  - Tears down its own spawn if `start()` fails (timeout, Ctrl+C) so machines
    aren't leaked.
- **Flag pattern scorer** (`src/bench_orchestrator/scoring/flag_pattern.py`):
  extracted the candidate-matching logic into a shared `extract_flag_candidate`
  helper.
- **HTB manifests** (`manifests/htb/*.yaml` and
  `manifests/htb/challenges/*.yaml`): switched scoring from `flag_pattern` to
  `verified_flags`; converted Diagnostic, Baby Time Capsule, and
  Distract and Destroy to the API-provisioned `htb_challenge` provider.
- **Dependencies**: added `websocket-client>=1.7` (`pyproject.toml`, `uv.lock`)
  for the HTB challenge websocket.
