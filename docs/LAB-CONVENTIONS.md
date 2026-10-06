# Lab conventions (contract for every lab in `labs/`)

Every lab MUST follow this layout and contract. No exceptions — the top-level
`scripts/verify-all.sh` relies on it.

## 1. Directory layout

```
labs/NN-slug/
  README.md            # player-facing brief. NO spoilers. Scenario + how to run + goal.
  WRITEUP.md           # full solution: theory, step-by-step exploitation, references
  docker-compose.yml   # everything needed to run the lab
  challenge/           # build context of the vulnerable service
    Dockerfile
    src/...            # the vulnerable app
    flag.txt           # (or generated in Dockerfile)
  solve/
    solve.py           # automated exploit (or solve.sh / solve.php)
  verify.sh            # build -> up -> wait -> solve -> assert flag -> down ; exit 0/1
  Makefile             # targets: up, down, solve, verify, logs, shell, clean
```

## 2. docker-compose.yml rules

* Top-level `name: phpctf-NN-slug` (unique compose project).
* The vulnerable service is called `challenge` and publishes on the host as
  `127.0.0.1:80NN:80` where `NN` is the lab number (lab 07 -> 8007).
  Extra services that must be reachable from the host use `127.0.0.1:90NN:...`.
* NEVER bind to `0.0.0.0`. These are deliberately vulnerable services.
* The exploit runs as a `solver` service, so the only host dependency is Docker:

```yaml
  solver:
    image: python:3.12-alpine        # or php:7.4-cli when the payload needs PHP
    profiles: ["solve"]
    volumes: ["./solve:/solve:ro"]
    working_dir: /solve
    command: ["python", "solve.py", "http://challenge"]
    depends_on: [challenge]
```

  invoked with `docker compose --profile solve run --rm --quiet-pull solver`.
* Pin base images to an exact tag (e.g. `php:7.4.33-apache`, not `php:latest`).
* Keep images minimal: no compilers/toolchains left in the final image unless
  the lab genuinely needs them; prefer the official `php:*` images.

## 3. Exploit rules

* `solve/solve.py` must use **Python 3 stdlib only** (`urllib`, `http.client`,
  `socket`, `re`, `base64`...). No `pip install` at solve time, no network egress.
* It takes the target base URL as `sys.argv[1]` (default `http://challenge`).
* It must print progress and end with the captured flag on the last line as
  `FLAG: PHRACK{...}`. Exit 0 on success, non-zero on failure.
* The exploit must be the *intended* solution of the challenge. If the lab has
  several intended paths, implement one and document the others in the writeup.

## 4. Flags

* Format: `PHRACK{...}` — lowercase words separated by `_`, unique per lab, e.g.
  `PHRACK{filter_chains_ate_my_local_file_inclusion}`.
* Stored at `/flag.txt` inside the challenge container (or wherever the
  challenge design requires, documented in the README).
* The flag must NOT be reachable without performing the intended technique
  (e.g. do not leave it readable by a plain `?page=/flag.txt` when the lab is
  about filter chains).

## 5. verify.sh contract

```sh
#!/usr/bin/env bash
# usage: ./verify.sh            (build, run, exploit, assert, clean up)
set -euo pipefail
```

* Must be runnable from any cwd (`cd "$(dirname "$0")"`).
* Waits for the service to be healthy (poll HTTP, max ~90s).
* Runs the solver, greps `PHRACK{` in the output, asserts it equals the lab flag.
* Always tears down (`trap` on EXIT: `docker compose down -v --remove-orphans`).
* Prints `VERIFY OK <lab>` or `VERIFY FAIL <lab>` and exits accordingly.
* Must be idempotent and must not leave containers/volumes behind.

## 6. README.md (player facing)

Sections, in order:
1. `# NN — Title` and a one-line hook.
2. **Article reference**: which section of the Phrack 72 article
   ("The Art of PHP - My CTF Journey and Untold Stories!", Orange Tsai) this lab
   recreates, plus the original CTF challenge/CVE it is based on.
3. **Difficulty** (easy / medium / hard / insane) and **category**.
4. **Run it**: `make up` + the URL, `make solve`, `make verify`, `make down`.
5. **Your goal**: one paragraph, no spoilers.
6. **Hints** (progressive, collapsed in `<details>` blocks) — 2 or 3 of them.
7. **What you will learn** (bullet list of techniques).
8. If the lab *emulates* something that cannot run in a Linux container
   (Windows APIs, Defender, ...), say so explicitly and precisely in a
   `> **Emulation notice**` blockquote: what is real PHP behaviour and what is
   modelled by a shim. Never let the player believe a shim is the real thing.

## 7. WRITEUP.md (full solution)

Sections, in order:
1. `# NN — Title — Writeup`
2. **TL;DR** — 3-5 lines.
3. **The bug** — the *why*: PHP internals, the relevant source snippet of the
   vulnerable app, the upstream commit/CVE when applicable.
4. **Building the exploit** — step by step, with the actual commands/payloads
   and their output. Show the intermediate primitives, not just the final one.
5. **The exploit** — the annotated final script, or a pointer to `solve/solve.py`
   with an explanation of each stage.
6. **Fixing it** — how a developer should have written the code.
7. **Going further** — variations, harder versions, related challenges.
8. **References** — links, credited to the original researchers/authors.

Write your own explanations and your own code. Do not copy text from the
article or from the referenced writeups: cite them with a URL instead.

## 8. Style

* English, technical, no fluff. Markdown, fenced code blocks with language tags.
* Credit the people named in the article (Orange Tsai, loknop, hashkitten,
  cfreal, remsio, icchy, Paul Axe, neex, Ryat Chen, Sam Thomas, ...) whenever the
  lab recreates their work.
* Keep the vulnerable code short and readable: the point is the technique, not
  a fake enterprise app. ~30-120 lines of PHP is the sweet spot.
* Add a `banner` or minimal CSS only if it costs nothing; do not build a UI.

## 9. Definition of done

A lab is done when `./verify.sh` exits 0 on a clean machine, README.md and
WRITEUP.md are complete, and `docker system prune` is not needed to re-run it.
