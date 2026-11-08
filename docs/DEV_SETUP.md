# Developer Setup & Tooling

## Prerequisites
- **Node.js**: v20+ (tested with v24)
- **Rust**: stable toolchain (`cargo`, `rustc`, `clippy`, `rustfmt`)
- **Python**: 3.11+ (recommended: virtual environment in `.venv/`)

## GSD Framework Installation (Per Developer)
GSD's local execution files are ignored in Git so that each developer maintains their own local runtime without committing generated workflows or machine-specific paths to the repository.

To install GSD locally for Antigravity in this repository, run:

```bash
npx --yes @opengsd/gsd-core@latest --antigravity --local
```

After installation:
1. **Restart Antigravity** to reload agent definitions, skills, and MCP configuration.
2. **Hook Execution Note on Windows**:
   GSD's generated hook wrappers in `.agents/settings.json` use POSIX shell substitution syntax (`"$(for n in ...; do ... done)"`). They require a Bash-capable shell environment (e.g. WSL or Git Bash). Under native Windows PowerShell or `cmd.exe`, these hook scripts are inert and will not execute as registered.
3. **MCP Server Pinning**:
   By default, GSD configures `.agents/mcp_config.json` to run an unpinned package (`npx -y -p @opengsd/gsd-core gsd-mcp-server`). For stability, pin this package to match `.agents/gsd-core/VERSION` (e.g. `@opengsd/gsd-core@1.20.1`).
   > **Note:** Running `gsd update` may regenerate `.agents/settings.json` and `.agents/mcp_config.json`. Always re-check and re-pin `.agents/mcp_config.json` after running any GSD update.

## Pull Request Reviews (CodeRabbit)
Automated code reviews are powered by CodeRabbit based on the `.coderabbit.yaml` configuration in the repository root. Pull requests opened against `main` are reviewed automatically.
