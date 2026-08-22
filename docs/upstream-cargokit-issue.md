# Upstream filing: cargokit swallows the build tool's exit code on Windows

**Status: drafted for you to read and post. Not filed.**

The content goes out under your name, so you should have read it first. Post it
yourself; do not have an agent publish to a third-party repository.

- **Repository**: <https://github.com/irondash/cargokit>
- **Also affects**: `flutter_rust_bridge`, which vendors cargokit into every
  generated project (`rust_builder/cargokit/`). Worth cross-referencing there
  once the issue exists.
- **Scope**: Windows only. One line.

---

## Issue title

`run_build_tool.cmd` does not propagate the build tool's exit code, so a failed
Rust build reports success on Windows

## Issue body

### Summary

On Windows, `run_build_tool.cmd` exits 0 even when the Dart build tool exits 1.
Gradle therefore treats a failed native build as a success and packages the
previous `.so`, producing an APK that looks correct and contains stale native
code.

`run_build_tool.sh` is not affected — it ends in `exit $exit_code`.

### Cause

A batch file returns the exit code of its last executed command. The last
command in `run_build_tool.cmd` is the `If` that checks for exit code 253:

```bat
"%DART%" "%PRECOMPILED%" %*

REM 253 means invalid snapshot version.
If %ERRORLEVEL% equ 253 (
    "%DART%" pub get --no-precompile
    "%DART%" compile kernel bin/build_tool_runner.dart
    "%DART%" "%PRECOMPILED%" %*
)
```

When the tool exits 1, the `If` condition is false, the `If` itself succeeds,
and the script returns 0.

Everything either side of the script is behaving correctly, which is what makes
this hard to spot:

- `build_tool.dart`'s `runMain` catches the error and calls `exit(1)`.
- Gradle's `exec` throws on a non-zero exit status.

The script between them converts the failure into a success.

### Reproduction

Minimal, without cargokit:

```bat
REM inner.cmd
@echo off
exit /b 1
```

```bat
REM outer.cmd — the same shape as run_build_tool.cmd
@echo off
setlocal
setlocal ENABLEDELAYEDEXPANSION
call "%~dp0inner.cmd"
If %ERRORLEVEL% equ 253 (
    echo retrying
)
```

```
> cmd /c outer.cmd
> echo %ERRORLEVEL%
0        <- expected 1
```

In a real project: introduce a compile error in the Rust crate and run
`flutter build apk`. The Rust step prints `SEVERE: Cargokit BuildTool failed
with error:` followed by the compiler output, and the build then reports
`√ Built build\app\outputs\flutter-apk\app-debug.apk`.

### Impact

The APK is packaged with whatever `.so` was there before. On a first build
there is no previous library and the failure surfaces later as
`dlopen failed: library "lib<name>.so" not found`. On a subsequent build the
APK carries the previous commit's native code and nothing indicates it — tests
run against stale code and pass.

### Suggested fix

Capture the status and return it:

```bat
"%DART%" "%PRECOMPILED%" %*
SET TOOL_EXIT=%ERRORLEVEL%

REM 253 means invalid snapshot version.
If %TOOL_EXIT% equ 253 (
    "%DART%" pub get --no-precompile
    "%DART%" compile kernel bin/build_tool_runner.dart
    "%DART%" "%PRECOMPILED%" %*
    SET TOOL_EXIT=!ERRORLEVEL!
)

exit /b %TOOL_EXIT%
```

`!ERRORLEVEL!` inside the block requires delayed expansion, which the script
already enables at the top.

Verified on Windows 11, Flutter 3.44, Gradle 9.1: with this change a failing
Rust build fails the Gradle build, and a succeeding one is unaffected.

---

## Pull request body

### What

`run_build_tool.cmd` returns the exit code of the build tool instead of always
returning 0.

### Why

A batch file returns the status of its last command. The last command was the
`If` that checks for exit code 253, which succeeds whether or not the build
failed — so a failed native build reported success, Gradle packaged the
previous `.so`, and the resulting APK contained stale native code with nothing
to indicate it.

`build_tool.dart` already calls `exit(1)` correctly and Gradle's `exec` already
throws on a non-zero status. Only the wrapper between them was losing the
signal. `run_build_tool.sh` already ends in `exit $exit_code`, so this brings
the Windows path in line with it.

### How it was verified

- Standalone reproduction of the batch behaviour (in the issue).
- In a real `flutter_rust_bridge` project on Windows 11 / Flutter 3.44 /
  Gradle 9.1: a deliberate Rust compile error now fails `flutter build apk`,
  where before it produced a successful build carrying the previous library.
  A clean build is unaffected.

### Risk

Windows only, and confined to how the script terminates. A build that
previously succeeded still succeeds; a build that previously reported success
while failing now fails.
