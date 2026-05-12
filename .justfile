default:
    just --list

# Update dependencies versions in lock files (no sync to venv)
upgrade-lock:
    uv lock --upgrade

# Perform vulnerability scan on project dependencies
audit:
    # "--no-resolve" to disable transitive dependency scanning for Maven pom.xml
    osv-scanner scan . --recursive --no-resolve

# Upgrade venv
sync-venv *ARGS:
    uv sync --frozen {{ ARGS }}

# Format check
format:
    ruff format --check --diff
# Fix format issues
fix-format *FILE:
    ruff format {{ FILE }}

# Static analysis
lint *FILE:
    ruff check {{ FILE }}
# Show fix to static analysis issue
lint-diff *FILE:
    ruff check --diff {{ FILE }}
# Apply fix to static analysis issue
fix-lint *FILE:
    ruff check --fix {{ FILE }}

# tests
test extra_param="-n auto --cov src":
    uv run pytest {{extra_param}} tests
    just packages/fib/test
    just packages/weekly/test

typing-mypy:
    uv run --with=pip mypy --install-types --non-interactive src

typing *PATH:
    ty check --exclude packages -v {{ PATH }}

check: lint format typing test
