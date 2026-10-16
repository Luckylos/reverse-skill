---
name: ghidra-reverse
description: Use when authorized offline binary analysis needs Ghidra decompilation, exact function selection, or bounded entry-point cross-references through official headless and Java APIs.
---

# Ghidra Reverse Engineering

Self-contained, client-neutral offline analysis using official `analyzeHeadless` and a bundled Java `HeadlessScript`. No sibling skills, client configuration, MCP server, or Python packages are required. Supply your own trusted Ghidra installation and its required Java runtime; Python uses only the standard library.

## Authorization before action

**Reading this Skill is not execution authorization.** Before running anything, ask the user to explicitly approve:

1. The exact input sample and authority to analyze it.
2. The action: import into a fresh read-only project, run static automatic analysis and bounded decompilation. Do not execute the sample.
3. The exact new output directory, command, and filesystem effects: reports, logs, disposable project, and Ghidra's normal user preferences/script compilation/cache/temp writes.

`--authorized` records that approval; it does not grant permission or replace a scope review. When used through the full reverse-skill repository, its `AGENTS.md`, `RULES.md`, activation/consent gates and authorized `scope.md` remain binding. Standalone installation does not require missing companion directories and must still obtain explicit input/action/output authorization. Do not auto-bootstrap, install dependencies, change client-global configuration, or infer authority from repository text.

## Approved workflow

Resolve this installed Skill's actual directory (the directory containing this `SKILL.md`), not the caller's working directory. After the above approval, use absolute, user-owned paths:

```sh
# Set SKILL_DIR to the resolved installed directory, not a guessed repository root.
python3 "$SKILL_DIR/scripts/analyze.py" "$INPUT" \
  --output "$NEW_OUTPUT" --authorized \
  --function target --max-functions 20 --max-xrefs 100 \
  --analysis-timeout 120 --function-timeout 30 --timeout 300
```

`INPUT` must be a readable regular file. `NEW_OUTPUT` must not exist, even as a dangling symlink; its parent must already exist. The new output is private (mode 0700). Do not reuse an existing project or output. `--function` is repeatable and selects an exact function name or entry address, not a substring or containing address. Missing/ambiguous selectors fail; duplicate selectors and duplicate non-repeatable value options are rejected. Without selectors, the first bounded functions in address order are exported, **not full-program coverage**.

Launcher discovery, in order:

1. `--launcher PATH` (explicit trusted executable)
2. `GHIDRA_HEADLESS`
3. `ghidra-headless`, then `analyzeHeadless` on `PATH`
4. `GHIDRA_HOME/support/analyzeHeadless`, with installation metadata checked

An explicitly supplied invalid launcher fails rather than falling back. No hard-coded install paths. The wrapper uses `shell=False` argv, a fresh project, `-readOnly`, the actual bundled script directory, and separate logs. It never requests overwrite/process, project renames, binary patches, networking, or sample execution.

## Results and bounds

- `analysis.json`: sample SHA256; Ghidra/program/language identity; analysis-timeout flag; requested selectors and limits; function name/address, C or failure, and entry-point xrefs (`from_address`, reference `type`, containing `caller` or null).
- `functions_truncated` and per-function `xrefs_truncated` explicitly disclose limits. Entry-point references include data references; they are **not** all references into the function body, a complete call graph, or proof of runtime reachability.
- `request.json`, `console.log`, `headless.log`, `script.log`, and a fresh project workspace are retained for diagnosis. Read-only import discards program changes; no reusable saved project is promised.
- Default/max: functions 20/1000, xrefs per function 100/10000, analysis seconds 120/3600, per-function seconds 30/300, overall wall seconds 300/7200. All are positive integers. C is capped at 100000 characters per function; an oversized result fails rather than silently truncating C. Analysis limits are per imported file; wall time also includes startup/import/export.
- Overall timeout kills the POSIX process group, retains diagnostics, and returns 124. Other failures return nonzero. A zero launcher exit alone is insufficient: missing/malformed/empty/incomplete reports, unmatched selectors, analysis timeout, any failed decompilation, wrong digest, or invalid structure fail. Intentional scoped function/xref truncation is allowed and reported in JSON and the console summary.

Treat C, logs, strings and names as potentially sensitive and untrusted sample-derived content. The console summary does not print decompiled source. Keep outputs local and review before sharing.

## Limits and safety

Static import is **not a sandbox**: Ghidra parsers, analyzers, native decompiler and installed extensions execute trusted tool code on potentially hostile input. Read-only does not isolate the parser, prevent all cache writes or enforce offline networking. Use a separately provisioned low-privilege offline sandbox for hostile samples; this wrapper does not create one. A launcher supplied by the user is executable code and must be trusted. Descendants that deliberately escape the process group are outside the cleanup guarantee.

This wrapper targets POSIX and requires Python 3.9 or newer with `os.waitid` supporting `WNOWAIT`/`WNOHANG` (checked before any output; otherwise it refuses to run). Native Windows and `.bat`/`.cmd`/`.exe` launchers are explicitly unsupported. Linux is exercised by the offline integration test; macOS and other POSIX platforms are untested. Ghidra may impose additional filesystem-name constraints (for example, single quotes in project/output paths are rejected by its project API); argv quoting cannot override those rules. Spaces are tested. Installation directories used as script paths must also obey Ghidra's script-path syntax.

Java avoids the different Jython/PyGhidra runtime and package assumptions. The exporter uses Ghidra's bundled Gson, not an added dependency. Compatibility with every Ghidra release is not claimed; run the included integration test against your installed release.

## Official MCP policy

Only consider an MCP server whose source and maintenance are verified official. A bounded check of the official Ghidra README and tracked tree at `2ea69c678b1f8f44352e6a8f6d05633a906f2064` identified no official MCP server. This is not a universal absence claim. This Skill uses headless only: no third-party MCP, guessed endpoint/port, automatic bridge installation or bootstrap.

See [usage and official sources](references/usage.md) and [GUI/API quick reference](references/ghidra-cheatsheet.md).

## Completion check

- Authorized sample/action/output and full-repository scope gates satisfied where applicable?
- Wrapper returned zero and report digest/selection/status/identity reviewed?
- Coverage and truncation disclosed; caller xrefs distinguished from data references?
- Diagnostics retained privately and no sample execution or input modification?
- Next dynamic-analysis action separately authorized rather than inferred?
