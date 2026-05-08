# devaudt

Deterministic static code analyzer for Python, TypeScript, and JavaScript repositories.

## Install

```bash
uv add /path/to/devaudt
```

Or from a local editable checkout:

```bash
uv pip install -e /path/to/devaudt
```

## Library usage

```python
from devaudt import analyze_local, analyze_url

# Analyze a local repository
result = analyze_local("/path/to/repo")

# Clone and analyze a remote repository
result = analyze_url("https://github.com/user/repo")

# Serialize to JSON
import json
print(json.dumps(result.to_dict(), indent=2))
```

## CLI usage

```bash
# Analyze a local path
devaudt --path /path/to/repo

# Clone and analyze a remote URL
devaudt --url https://github.com/user/repo

# Write output to a file
devaudt --path /path/to/repo --output result.json
```

## Requirements

- Python 3.12+
- Node.js (optional — enables full TypeScript/JavaScript analysis; falls back to regex-only without it)
