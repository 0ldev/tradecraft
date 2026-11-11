# Running Tradecraft in Docker (`docs/setup.md`)

For running Tradecraft against a real target without installing ~150
tools' worth of binaries on your own machine. For local development
without Docker, see the README's Setup section instead.

## Building

Three build targets, each a superset of the last (`Dockerfile`):

```bash
docker build --target slim -t tradecraft:slim .   # core + ~70 pure-Python tools, Go recon/web scanners, nmap, sqlmap
docker build --target web  -t tradecraft:web  .   # + Chromium/Playwright, GoWitness, PHP/phpggc, ysoserial, WhatWeb/WPScan, retire.js, kiterunner, hydra, cewl, cupp
docker build --target full -t tradecraft:full .   # + every tool across the web, ad-network, cloud, and kubernetes profiles
```

Pick the smallest target that covers the profile(s) you'll actually
run (`docs/profiles.md`) — `full` is the biggest image and only buys
you anything if you need `ad-network`/`cloud`/`kubernetes` tools too.

## Configuring

```bash
cp .env.example .env
# set LLM_BASE_URL, LLM_MODEL, LLM_API_KEY at minimum
```

A few tools use optional API keys from the same `.env`
(`GITHUB_TOKEN`, `SHODAN_API_KEY`, ...) — see `.env.example` for the
full list. A missing optional key just means that one tool/feature
degrades or is skipped; it's never a hard failure.

## Running

```bash
docker run --rm -it \
  --env-file .env \
  -v ~/.tradecraft:/root/.tradecraft \
  tradecraft:web 10.0.0.5 --profile web --report
```

- `-v ~/.tradecraft:/root/.tradecraft` is what makes a run's data (and
  `tradecraft chat`/`report`/`dataset`/`memory`'s view of it) survive
  past the container exiting — `$TRADECRAFT_HOME` defaults to
  `~/.tradecraft` both inside the container and in a normal local
  install, so this is the one mount that actually matters.
- Two more are worth adding so `nuclei`/`trivy` don't re-download
  their templates/vulnerability DB on every container run:
  `-v nuclei-templates:/root/nuclei-templates` and
  `-v trivy-cache:/root/.cache/trivy` (named volumes, or host paths).
- If your LLM endpoint is on `127.0.0.1` on the host, or you're
  scanning through a host VPN/TUN interface, add `--network host`
  (Linux only) instead of relying on container networking.
- For a long-running/unattended scan, run detached instead of `-it`:
  `docker run -d --name tradecraft-run --env-file .env -v ~/.tradecraft:/root/.tradecraft tradecraft:web <target> ...`.

## Getting logs out

- **Attached (`-it`, no `-d`):** output streams directly to your
  terminal — this *is* the engagement log as it happens
  (`_on_event` in `tradecraft/cli.py`).
- **Detached (`-d --name tradecraft-run`):**
  ```bash
  docker logs -f --tail 100 tradecraft-run   # follow live
  docker ps                               # check it's still running
  docker stop tradecraft-run && docker rm tradecraft-run   # stop/clean up
  ```
- **The structured data** (independent of container stdout) is
  whatever ended up under the mounted `$TRADECRAFT_HOME` — see the next
  section. It's there whether you were watching `docker logs` or not,
  and survives after the container is removed.

## Extracting what's inside a run

Everything a run produces lands under
`$TRADECRAFT_HOME/targets/<target>/runs/<run_id>/` on your host (via the
`~/.tradecraft` mount above) — `manifest.json`, `log.txt`, `trace.jsonl`,
`facts.json`, `evidence/`, and `report.<ext>` if `--report` was used.
You don't need the container running, or even still existing, to read
any of this — it's plain files on disk. See `docs/cli.md`'s full
flag reference for each of these; in short:

- **A human-readable report:** `tradecraft report --target <target>` — see `docs/report.md`.
- **Ask questions about a specific run:** `tradecraft chat --target <target> --ask "..."` — see `docs/post-engagement.md`.
- **Search across every run you've indexed:** `tradecraft memory index --target <target>` then `tradecraft memory search "..."`.
- **Fine-tuning data:** `tradecraft dataset --target <target> --format sft,dpo` — see `docs/finetune.md`.

All four can run either inside another container invocation (same
image, same `-v ~/.tradecraft:/root/.tradecraft` mount) or from a local
`pip install -e .` checkout pointed at the same `$TRADECRAFT_HOME` — the
run data on disk doesn't care which one produced or reads it.
