#!/usr/bin/env bash
# Copyright (c) 2026 bata94
# SPDX-License-Identifier: MIT WITH Commons-Clause

set -euo pipefail

BUMP="${1:-patch}"
PREFIX="v"
VERSION_FILE="VERSION"
BRANCH="main"

# ---------- read current version ----------
CURRENT_VER="$(cat "$VERSION_FILE" 2>/dev/null || echo "0.0.0")"

IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VER"
MAJOR=${MAJOR:-0}
MINOR=${MINOR:-0}
PATCH=${PATCH:-0}

# ---------- check for uncommitted changes ----------
if ! git diff --quiet -- "$VERSION_FILE"; then
  echo "Error: $VERSION_FILE has uncommitted changes"
  exit 1
fi

# ---------- bump ----------
case "$BUMP" in
  major)
    MAJOR=$((MAJOR + 1))
    MINOR=0
    PATCH=0
    ;;
  minor)
    MINOR=$((MINOR + 1))
    PATCH=0
    ;;
  patch)
    PATCH=$((PATCH + 1))
    ;;
  *)
    echo "Usage: $0 {patch|minor|major}"
    exit 1
    ;;
esac

NEW_VER="${MAJOR}.${MINOR}.${PATCH}"
NEW_TAG="${PREFIX}${NEW_VER}"

# ---------- fail if tag already exists ----------
if git rev-parse "$NEW_TAG" >/dev/null 2>&1; then
  echo "Error: tag $NEW_TAG already exists"
  exit 1
fi

# ---------- changelog ----------
LATEST_TAG=$(git tag --list "${PREFIX}*" --sort=-version:refname | head -n 1 2>/dev/null || true)
if [ -z "$LATEST_TAG" ]; then
  ALL_COMMITS=$(git log --oneline)
  RANGE_LABEL="beginning"
else
  ALL_COMMITS=$(git log --oneline "$LATEST_TAG..HEAD" 2>/dev/null || true)
  RANGE_LABEL="$LATEST_TAG"
fi

FILTERED=$(echo "$ALL_COMMITS" | grep -iE '^(feat|fix|perf|refactor|docs|test|chore|ci|build|revert)(\([^)]+\))?!?:' || true)
if [ -n "$FILTERED" ]; then
  CHANGELOG="$FILTERED"
elif [ -n "$ALL_COMMITS" ]; then
  CHANGELOG="$ALL_COMMITS"
else
  CHANGELOG="No changes since $RANGE_LABEL"
fi

# ---------- write VERSION, commit, tag ----------
echo "$NEW_VER" > "$VERSION_FILE"

git add "$VERSION_FILE"
git commit -m "chore: bump version to ${NEW_VER}"

git tag -a "$NEW_TAG" -m "Release $NEW_TAG" -m "$CHANGELOG"

# ---------- push ----------
echo ""
echo "Ready to push:"
echo "  git push origin $BRANCH"
echo "  git push origin $NEW_TAG"
echo ""
read -r -p "Push now? [Y/n] " REPLY
REPLY="${REPLY:-y}"
case "$REPLY" in
  [Yy]*)
    git push origin "$BRANCH"
    git push origin "$NEW_TAG"
    echo "Done: $NEW_TAG"
    ;;
  *)
    echo "Push cancelled. Run manually:"
    echo "  git push origin $BRANCH && git push origin $NEW_TAG"
    ;;
esac
