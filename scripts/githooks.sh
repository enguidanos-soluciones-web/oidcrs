#!/bin/bash
set -e

echo "Installing git hooks..."
git config core.hooksPath scripts/githooks
echo "...git hooks installed!"
