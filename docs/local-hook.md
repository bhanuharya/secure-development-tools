# The pre-commit check: findings on the developer's machine, before the commit

`sdt scan --staged` checks the lines a commit is about to add for secrets and code
weaknesses, with the same rule pack and the same policy as the scan of the pull
request. Run as a git pre-commit hook, it stops the commit and says where and why:

```console
$ git commit -m "host check"
sdt: 2 problems in the lines being committed must be fixed first

  app/settings.py:2  high  secret (github-pat)
      Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure.
      Take it out before you commit. It has to be replaced only if it was pushed or shared before.
  app/tool.py:9  high  injection.subprocess-shell  (+2 more rules on this line)
      Shell execution interprets metacharacters and can enable command injection. Pass an argument list with shell=False.

Fix and commit again. To commit as it is: SKIP_SDT=1 git commit ... (the pull request scan reports the same).
Full report: .git/sdt/reports/findings.json
```

A commit with nothing to report gets one line. The check is an early warning: it
runs where the developer can switch it off, so the scan of the pull request stays
the gate.

## Setting it up

Each developer needs three programs on `PATH`: `sdt`, OpenGrep 1.29.0 and Gitleaks
8.30.1 (`sdt doctor` checks them). Then one of:

**sdt's own hook.** Build `sdt` in a checkout of this repository and leave it
there; a link on `PATH` is fine. It reads the rule pack from that checkout.

```bash
git clone https://github.com/bhanuharya/secure-development-tools.git
cd secure-development-tools && go build -o sdt ./cmd/sdt
ln -s "$PWD/sdt" ~/.local/bin/sdt

cd /path/to/a/repository
sdt hook install          # writes the pre-commit hook; `sdt hook uninstall` removes it
```

Updating is `git pull` and the same build. The hook is per clone: git does not
copy hooks, so every developer runs `sdt hook install` once in every repository.

**The pre-commit framework** ([pre-commit.com](https://pre-commit.com)). The
configuration is committed, so the team shares the hook and its version.
pre-commit builds `sdt` itself (it needs Go, or fetches it).

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/bhanuharya/secure-development-tools
    rev: <commit>
    hooks:
      - id: sdt
```

**Another hook manager** (husky, lefthook) or a hook the repository already has:
add the line `sdt scan --staged || exit 1`. `sdt hook install` does not replace a
hook it did not write, and it follows `core.hooksPath`.

If the rule pack is somewhere else, name it: `SDT_RULES_PACK_DIR=/path/to/rules/opengrep-rules`.

## What is checked

- **The lines the commit adds or changes.** A weakness that was already in a file
  is not reported when another line of that file changes. That one is in the
  report of the pull request and the fleet scan.
- **The files as they are staged.** With `git add -p`, what is left unstaged is
  not read.
- **Secrets** (Gitleaks, with sdt's defaults and the repository's own
  `.gitleaks.toml` and `.gitleaksignore`) **and code rules** (OpenGrep, with the
  rules for the languages of the staged files).
- **With the policy of the pull request scan**, including `.secure-dev.yaml`,
  the baseline and the exceptions of the repository when it has them. What blocks
  here blocks there.

## What is not checked

- **Dependencies.** Trivy needs the whole tree and its database; it runs in CI.
- **SonarQube's own analysers**, which run on the server.
- **A flow that ends on a line the commit does not touch.** A rule reports a flow
  where the data is used. When a commit only changes where the data comes from,
  the finding is on an unchanged line and is left to CI.
- **A commit that concludes a merge.** Its changes are mostly other people's
  commits, which were checked when they were made and are scanned again in CI.
- **What is already in history.** A secret committed last year is found by the
  full scan, not here.

## How long it takes

Measured on one Linux machine (14 cores), three commits of each kind. The time
does not depend on the size of the repository: only the staged files are read.

| The commit changes | Seconds |
|---|---|
| Only removes or renames | under 0.1 |
| Text, no code | 2.3, 2.9, 4.4 |
| PHP | 2.7, 2.8, 2.8 |
| Go | 3.0, 3.6, 4.6 |
| Java | 3.2, 3.3, 3.4 |
| JavaScript | 3.2, 3.3, 3.4 |
| TypeScript | 3.1, 3.1, 3.8 |
| YAML | 3.0, 3.5, 3.6 |
| Python | 3.7, 3.9, 4.0 |

About 2 s of every run is the code scanner starting. Most of the rest is reading
the rules, which is why only the rules for the staged files' languages are
loaded; with all rules loaded a commit took 6 s. Before 2026-10-13 the staged
scan read the whole working tree and took as long as a full code scan.

## Committing anyway

`SKIP_SDT=1 git commit ...` skips this check and no other hook. It works with
every way of setting it up. A rule that is wrong about a line is a reason to use
it, and to report the rule (see [`rule-precision.md`](rule-precision.md)): the
rules added in October 2026 have not been through a shadow triage yet, so some of
them will block lines that are fine.

When a scanner is missing the commit is stopped with that message, not passed.
When `sdt` itself is missing, the hook written by `sdt hook install` lets the
commit through with a note.

## Where its files go

Reports and cache are written to `.git/sdt/`, not to the working tree. The staged
files are copied to a temporary directory for the scan and removed after it.

## Not done

- **Windows.** `sdt` compiles for Windows since 2026-10-13, and the hook is a
  shell script that Git for Windows runs. It has not been run there, and neither
  have the Windows builds of the two scanners. WSL behaves as Linux.
- **A server-side check.** A local hook can be skipped or never installed. Blocking
  a push needs a hook on the server or the pull request gate.
- **A script without an extension** (first line `#!`) makes a commit load every
  rule, about 6 s: the code scanner reads the interpreter from that line and sdt
  does not.
