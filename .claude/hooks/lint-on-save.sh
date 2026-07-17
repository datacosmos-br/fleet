#!/bin/sh
# PostToolUse hook: validate the edited source without mutating it.
set -eu

INPUT=$(cat)
FILE_PATH=$(printf '%s' "$INPUT" | jq -r '.tool_input.file_path // empty')
[ -n "$FILE_PATH" ] || exit 0

PROJECT_DIR=${CLAUDE_PROJECT_DIR:-}
if [ -z "$PROJECT_DIR" ] || [ ! -d "$PROJECT_DIR" ]; then
  printf 'lint-on-save: CLAUDE_PROJECT_DIR is required and must exist\n' >&2
  exit 2
fi

case "$FILE_PATH" in
  "$PROJECT_DIR"/*) TARGET=${FILE_PATH#"$PROJECT_DIR"/} ;;
  /*)
    printf 'lint-on-save: file is outside project root: %s\n' "$FILE_PATH" >&2
    exit 2
    ;;
  *) TARGET=$FILE_PATH ;;
esac
case "/$TARGET/" in
  */../*)
    printf 'lint-on-save: parent traversal is forbidden: %s\n' "$TARGET" >&2
    exit 2
    ;;
esac

cd "$PROJECT_DIR" || exit 2

emit_failure() {
  label=$1
  output=$2
  jq -n --arg fp "$TARGET" --arg label "$label" --arg output "$output" \
    '{hookSpecificOutput: {hookEventName: "PostToolUse", additionalContext: ($label + " failed for " + $fp + ":\n" + $output)}}'
}

run_check() {
  label=$1
  shift
  output=""
  if ! output=$("$@" 2>&1); then
    emit_failure "$label" "$output"
    exit 2
  fi
}

case "$TARGET" in
  third_party/*|*/third_party/*) exit 0 ;;
  *.go)
    if [ ! -f Makefile ] || ! grep -q '^lint-go-incremental:' Makefile; then
      printf 'lint-on-save: canonical lint-go-incremental target is missing\n' >&2
      exit 2
    fi
    run_check "make lint-go-incremental" make lint-go-incremental
    ;;
  *.ts|*.tsx|*.js|*.jsx)
    run_check "yarn prettier --check" yarn --silent prettier --check "$TARGET"
    run_check "yarn eslint" yarn --silent eslint "$TARGET"
    ;;
  *.scss|*.css)
    run_check "yarn prettier --check" yarn --silent prettier --check "$TARGET"
    ;;
esac
