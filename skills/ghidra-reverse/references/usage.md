# Installation, usage, and official sources

## Standalone import

Keep the entire `skills/ghidra-reverse` subtree together (`SKILL.md`, `scripts`, `references`, and optionally `tests`). There are no companion-directory requirements. Install into a user-chosen Skill location using your client's documented local import mechanism; this document does not prescribe an unverified CLI install command or edit global configuration.

For Magpie's GitHub source import, use this **subdirectory URL**, not the repository root:

<https://github.com/Luckylos/reverse-skill/tree/main/skills/ghidra-reverse>

Static source confirmation: [yetone/magpie `internal/library/skills.go` at 138188a36de6e77a1d2c5d331814c336aea32663](https://github.com/yetone/magpie/blob/138188a36de6e77a1d2c5d331814c336aea32663/internal/library/skills.go). Its `githubSource` supports this subtree source; `ProbeSkills` starts at `src.Path`, and `candidates(root, start)` stops descending once it finds a `SKILL` file. Therefore the root source is not equivalent and will not separately enumerate this nested module. This is static implementation confirmation, **not an actual Magpie UI installation test**. Check the imported file tree before execution.

After installation, resolve the directory containing this Skill's `SKILL.md`. Set `SKILL_DIR` explicitly to that resolved location and use the invocation in `SKILL.md`; do not assume the current directory is the Skill or repository root. Keep output outside the installed Skill and under user control. Reviewing/importing files alone authorizes no script execution.

## Runtime and output ownership

Use an existing official Ghidra distribution, its compatible Java runtime, and Python 3.9+. Discover/configure a trusted POSIX `analyzeHeadless` launcher; no dependencies are downloaded or auto-installed. Java scripts use `HeadlessScript`, `DecompInterface`, the program/function/reference APIs, and bundled Gson. Jython and PyGhidra are not required.

The wrapper creates one new private output directory, logs and a disposable fresh project, and never calls `-process` or `-overwrite`. Ghidra also normally writes user preferences, compiled Java scripts, caches and temporary files outside the output. Disclose and approve those effects. For isolated testing, Java system properties must be configured explicitly: `user.home`, `java.io.tmpdir`, `application.cachedir`, and `application.tempdir`. Merely changing `HOME` is insufficient. JVM `JAVA_TOOL_OPTIONS` uses its own quoting: enclose property values containing spaces in double quotes. This is cache placement, not sandboxing; tool-specific extensions may have other behavior.

Launcher lifecycle: the CLI resets `SIGCHLD` to its default disposition (an inherited ignore would auto-reap the launcher), starts the launcher in a new session, and observes its exit with `os.waitid(P_PID, pid, WEXITED | WNOWAIT | WNOHANG)` without reaping it. On every terminal path where the leader is still its unreaped child (exit, timeout, interrupt, observation error) it SIGKILLs the launcher's process group while the unreaped leader still pins that PID/PGID, then reaps the leader exactly once and never signals that number again. If something else already reaped the leader, it sends no signal and fails. Python builds lacking `os.waitid`, `WNOWAIT` or `WNOHANG` are refused before any output is created; there is no unsafe fallback. Descendants that leave the group (`setsid`/`setpgid`) are not cleaned.

Inspect `analysis.json` and private diagnostics on nonzero exit. Do not treat retained files as a successful result. Preserve the SHA256, program/language identity and addresses when reporting evidence. Functions are exported in address order without selectors; an explicit selector matches a unique exact name or entry-point address. Overlapping selectors may identify one function. A name resolving to multiple functions is reported as unmatched/ambiguous. All reported xrefs target only the entry address, including non-call references with null callers. Function/xref limits intentionally restrict scope and must be disclosed in findings.

## Offline regression test

After approving the test command and generated fixture/cache writes, run from the repository root:

```sh
GHIDRA_HEADLESS="$TRUSTED_HEADLESS_LAUNCHER" PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s skills/ghidra-reverse/tests -p 'test_*.py' -v
```

For a standalone directory, use `-s "$SKILL_DIR/tests"` instead. Approve an existing scratch directory: tests default to the repository's parent directory for the full-repo layout; standalone users should explicitly set `GHIDRA_TEST_SCRATCH` to an approved existing directory. This fixture location is not an installation or runtime discovery path. All generated fixtures and test JVM properties point into that workspace. Test directories are cleaned on exit; production diagnostics are retained.

Tests require a local `cc` or `gcc`, `GHIDRA_HEADLESS`, Linux `/proc`, `os.pidfd_open` and `signal.pidfd_send_signal`. No skips or automatic installs. Failure cleanup signals a controlled fixture child only through a pidfd verified against a unique per-case argv marker; there is no numeric-PID kill. They compile a generated owned ELF but **never execute it**. They check real C export, a known caller reference, exact address selection, unmatched selection failure and truncation, plus lightweight local launcher fixtures for invalid reports, quoting and process-group timeout cleanup. The integration test covers Linux; no broad platform/release matrix is implied. The tested machine version belongs in a delivery report, not this portable Skill.

## Official references

- [Official Ghidra source and releases](https://github.com/NationalSecurityAgency/ghidra)
- [Official installation guide](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/InstallationGuide.md)
- [Headless analyzer README (fixed source)](https://github.com/NationalSecurityAgency/ghidra/blob/2ea69c678b1f8f44352e6a8f6d05633a906f2064/Ghidra/RuntimeScripts/Common/support/analyzeHeadlessREADME.md): read-only import, script arguments/paths/logs, analysis timeout, fresh projects.
- [HeadlessScript source (fixed source)](https://github.com/NationalSecurityAgency/ghidra/blob/2ea69c678b1f8f44352e6a8f6d05633a906f2064/Ghidra/Features/Base/src/main/java/ghidra/app/util/headless/HeadlessScript.java): `analysisTimeoutOccurred()` and script semantics.
- [Official Java API](https://ghidra.re/ghidra_docs/api/): `ghidra.app.decompiler.DecompInterface`, `DecompileResults`, `ghidra.program.model.listing.FunctionManager`, `ghidra.program.model.symbol.ReferenceManager`.
- [Official launch properties](https://github.com/NationalSecurityAgency/ghidra/blob/2ea69c678b1f8f44352e6a8f6d05633a906f2064/Ghidra/RuntimeScripts/Common/support/launch.properties): application user/cache/temp settings.

Use your installed release's headless README/API for version-specific details. Official-source eligibility is mandatory for any future MCP integration. No official server was identified in the bounded README/tree inspection at the fixed revision above; no MCP implementation or endpoint is included here.
