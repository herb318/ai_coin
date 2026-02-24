# Docker Automation

Run the full DPUIN validation pipeline in one command.

## 1) One-shot (default, non-production)

```bash
docker compose run --rm --build oneshot
```

This executes, in order:
- unit tests
- Bandit security scan
- secret/PII sanitize scan
- QA suite
- demo run
- status report generation

Generated status outputs:
- `docs/NETWORK_STATUS.md`
- `docs/NETWORK_STATUS.json`
- `docs/NETWORK_HISTORY.jsonl`

## 2) One-shot strict production checks

Prepare `.env` first:

```bash
cp .env.example .env
# fill with real private values
```

Run strict mode:

```bash
docker compose --profile production run --rm --build oneshot-prod
```

## 3) Long-running operator loop (container)

```bash
docker compose --profile operator up --build operator-loop
```

Stop:

```bash
docker compose --profile operator down
```

## 4) Direct docker run (without compose)

```bash
docker build -t dpuin-protocol:local .
docker run --rm -v "$(pwd):/app" dpuin-protocol:local --mode oneshot
```
