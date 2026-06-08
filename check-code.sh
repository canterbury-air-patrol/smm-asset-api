#!/usr/bin/env bash

set -euo pipefail

# Static code checks: formatting, cppcheck, and clang-tidy.
#
# Run from the top of the source tree after building with a compile database
# (e.g. `bear -- make`), which clang-tidy needs via compile_commands.json.
#
# File sets are globbed rather than enumerated so new sources are covered by
# the gate automatically.

# clang-format output is not stable across major versions. The tree is
# formatted with clang-format 22.1.x; CI pins that exact version and points
# CLANG_FORMAT at it. Locally, set CLANG_FORMAT if your system clang-format
# is a different major version.
clang_format="${CLANG_FORMAT:-clang-format}"
"$clang_format" --dry-run -Werror src/*.c src/*.h tests/*.c

cppcheck --enable=warning,performance,portability,style --error-exitcode=1 \
	--inline-suppr --std=c11 -I src src/*.c

# The clang-tidy gate is enforced primarily by WarningsAsErrors in .clang-tidy:
# run-clang-tidy then exits non-zero and `set -o pipefail` fails the pipeline.
# HeaderFilterRegex already restricts diagnostics to our own sources. The grep
# below is a backstop that matches clang-tidy's "path:line:col: warning:"
# diagnostic format rather than any stray "warning"/"error" word in the output.
run-clang-tidy -p . 'src/.*\.c$' 2>&1 | tee clang-tidy.log
! grep -Eq ': (warning|error):' clang-tidy.log
