# INSTALL.md: the laptop evaluation install

**Reader:** someone evaluating Polaris on a Mac with the double-click
launcher. **Job:** the long-form companion to the README's quickstart:
what the launcher does, what it needs, and what to do when a step fails.
A server deployment is [DEPLOYMENT.md](DEPLOYMENT.md), not this page.

The laptop stack signs with a named development placeholder, not ML-DSA-65, so `polaris-verify`
reports what it issues as not authenticatable. Real signing is the production image.


## Prerequisites

| Component       | Required version | How to get it                                            |
|-----------------|------------------|----------------------------------------------------------|
| macOS           | 11 (Big Sur) +   | Built in                                                 |
| Docker Desktop  | Any current      | [docker.com/products/docker-desktop](https://docker.com) |
| Web browser     | Any modern       | Built in                                                 |

That's the entire prerequisite list for the recommended Docker path.
The launcher also supports a native fallback (Homebrew + local Postgres)
if you don't want to install Docker, but Docker is significantly easier.

Polaris does **not** require:
- A Python installation on the host (it lives inside the container)
- A Postgres installation on the host
- Any pip / brew packages
- Admin / sudo privileges (Docker Desktop installation aside)
- An internet connection at runtime (only at first build, to pull
  `python:3.12-slim` and `postgres:16` images)


## First run

1. Either `git clone https://github.com/EgorKhaklin/polaris-id.git` OR
   download a release zip from the GitHub Releases page and double-
   click to extract. macOS will produce a `polaris/` folder.

2. Drag the `polaris/` folder somewhere persistent: `~/Desktop`,
   `~/Documents`, `~/Code`, anywhere. Don't leave it inside the
   `Downloads` folder; macOS sometimes treats Downloads specially.

3. Open the `polaris/` folder. Find `Polaris.command`.

4. **Right-click `Polaris.command` → Open → Open.**

   This is required exactly once. macOS Gatekeeper requires explicit
   approval before running unsigned scripts downloaded from the
   internet. Right-click → Open is the official way to grant that
   approval. Subsequent double-clicks work normally.

   (`Polaris.command` strips the quarantine attribute from the rest
   of the bundle on first run, so you only have to do this for the
   `.command` file itself.)

5. A Terminal window opens. The launcher does the following in order:

   - Strips quarantine attributes from the bundle
   - Detects whether Docker Desktop is running; starts it if not
     (waits up to 90 seconds for the daemon socket)
   - Builds the Flask container image
   - Starts Postgres 16 with the schema, sample data, and grants
     loaded automatically by the init scripts
   - Waits for both services to become healthy
   - Opens your browser to the login page
   - Stays in the foreground, watching for the browser tab

6. The first build pulls ~150 MB of base images and runs `pip install`
   for Flask, psycopg2, and gunicorn. Expect 2–4 minutes of "first run"
   time. The Terminal window will show progress.

7. When you see `Polaris is LIVE at http://localhost:2222`, your
   browser will pop the login page automatically. The default
   credentials are printed in the Terminal output:

   ```
   admin     /  Admin@123!
   operator  /  Operator@123!
   auditor   /  Auditor@123!
   ```


## Subsequent runs

Just double-click `Polaris.command`. Docker Desktop starts automatically
if it isn't already running. The image and volume from the first run
are reused; bring-up takes about 10 seconds.


## Stopping Polaris

Three ways, all equivalent:

- **Close the browser tab.** The launcher detects the tab close via a
  `sendBeacon` call and tears the stack down within a couple of seconds.
- **Press `Ctrl+C` in the Terminal window.** Same effect, immediate.
- **Run `./polaris_mac_launch.sh stop` from another Terminal window.**

If you closed Terminal without stopping the stack first, that is fine;
the Docker stack stays running in the background. Reopen Terminal in
the polaris folder and run `./polaris_mac_launch.sh stop`.


## Changing the port

Default is `2222`. If something else is on that port:

```bash
./polaris_mac_launch.sh up --port 5050
```

Or to make a port change permanent, edit one line in `polaris_mac_launch.sh`:

```bash
DEFAULT_PORT=5050      # change from 2222
```


## Running tests

```bash
./polaris_mac_launch.sh test
```

This requires the stack to be up first (the tests connect to the
running Postgres). Expected output:

```
467 passed, 12 skipped        # polaris_web/test_app.py (v9.236; skips need optional backends)
OK
```

Plus the C1-C10 invariant check layer (`python3 -m polaris_checks.run`)
and the optional property tests (`test_invariants_property.py`,
`test_redaction_property.py`, if Hypothesis is installed).

The SQL self-tests (78 assertions in `08_tests.sql` at v9.194, plus
`12_v7_constraints.sql` and `13_substrate.sql`) run automatically when
the Postgres container initializes; their results are visible in
`./polaris_mac_launch.sh logs db`.


## Troubleshooting

### "Apple cannot check it for malicious software"

You double-clicked `Polaris.command` instead of right-click → Open →
Open. Close the warning. Right-click `Polaris.command` and choose Open
from the context menu. macOS will then offer an `Open` button that
isn't there on a normal double-click. Click it. Done; you only need
to do this once.

### `ERR_EMPTY_RESPONSE` in browser

The port forwarder exists but nothing is listening behind it. Causes:

- **Stack still booting.** First-run image build takes 2–4 minutes.
  Check the Terminal output for `Polaris is LIVE at …`.
- **Container in restart loop.** Run `./polaris_mac_launch.sh doctor`.
  If it reports `polaris-app is in a restart loop`, run
  `./polaris_mac_launch.sh logs app` to see why.
- **Stale browser cache.** Hard-refresh with `Cmd+Shift+R`, or open
  the URL in a private/incognito window.
- **macOS AirPlay Receiver on port 5000.** Doesn't apply on the default
  port 2222. Only relevant if you've set `--port 5000`.

### `connection to server at "db" failed: password authentication failed`

Your Postgres data volume was initialized with one password and the
app is trying to use another. The launcher self-heals this:

```bash
./polaris_mac_launch.sh rebuild
```

If the auto-heal doesn't trigger for some reason:

```bash
./polaris_mac_launch.sh nuke
./polaris_mac_launch.sh up
```

### `polaris-db exited (126)`

Exit code 126 is "container command not executable". The init script
`docker-init.sh` lost its execute bit during zip extraction. The
launcher restores it on every `up`, so just run:

```bash
./polaris_mac_launch.sh up
```

If it still happens, manually:

```bash
chmod +x polaris_web/docker-init.sh
./polaris_mac_launch.sh rebuild
```

### `Docker not running. Start Docker Desktop and retry.`

The launcher tried to auto-start Docker Desktop and timed out after
90 seconds. Open Docker Desktop manually from `/Applications`, wait
for the menu-bar whale to stop animating, then re-run the launcher.

If Docker Desktop is not installed, install it from
[docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop)
or use the native fallback: `./polaris_mac_launch.sh up --native`.

### Login page loads, but POST returns 500

Almost certainly stale-volume credential drift. See the auth-failure
section above. Run `./polaris_mac_launch.sh doctor` to confirm.

### Login succeeds, but dashboard returns 500

The launcher self-heals the most common cause (stale volume), so this
is rare. Capture the traceback:

```bash
./polaris_mac_launch.sh logs app | tail -100
```

The traceback will name the failing query or template line. Most
likely a SQL column-name mismatch from a partial schema update.

### Watch mode shut down the stack while I was using it

The launcher gives the browser 90 seconds to start beating after
launch, then expects a heartbeat every 10 seconds. If your browser
stops sending heartbeats for 45+ seconds (sleeping laptop, lost
network, browser crashed), the launcher assumes you're done and shuts
down. To opt out:

```bash
./polaris_mac_launch.sh up --detach
```

`--detach` skips the watcher. The stack stays up until you explicitly
stop it.

### I want to start completely over

```bash
./polaris_mac_launch.sh nuke
./polaris_mac_launch.sh up
```

`nuke` removes all polaris containers, the polaris_web-app image, the
postgres data volume, and the runtime state directory. After this, the
next `up` rebuilds from absolute zero.


## Native (no-Docker) installation

If you don't want to install Docker Desktop, the launcher can run
Polaris natively against a Homebrew-installed Postgres:

```bash
./polaris_mac_launch.sh up --native
```

This requires Homebrew (`brew.sh`). The launcher will:

1. Install Postgres 16 via Homebrew if not already present
2. Initialize a Polaris cluster
3. Load the SQL package
4. Create a Python virtualenv
5. Install Flask, psycopg2, gunicorn
6. Start gunicorn and open the browser

Native mode is slower on first run (10+ minutes for Homebrew + pip)
but doesn't require Docker. Use Docker if you have any choice.


## Uninstall

To remove Polaris cleanly:

```bash
./polaris_mac_launch.sh nuke         # remove containers, image, volume
rm -rf ~/polaris                     # or wherever you cloned it
docker rmi postgres:16 python:3.12-slim 2>/dev/null   # optional
```

This leaves Docker Desktop installed; uninstall that separately if you
no longer need it.


## Getting help

If `./polaris_mac_launch.sh doctor` reports everything as `OK` but the
app still misbehaves, the issue is probably specific to your sample
data or browser state. The traceback in `./polaris_mac_launch.sh logs
app` is almost always the fastest path to a fix.
