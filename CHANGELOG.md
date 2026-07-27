# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-27

### Added

- Rule engine that runs a catalog of security checks over an MCP surface and
  gates CI on a configurable severity threshold.
- 18 built-in rules across permissions, schema hygiene, prompt injection,
  secret exposure, transport security, metadata leaks, and general hygiene.
- Transports: connect to MCP servers over stdio (spawned command) and HTTP/SSE.
- Static mode: lint a server's declared surface from a JSON manifest without
  executing it.
- Reporters: colored terminal output, JSON, and SARIF 2.1.0 for GitHub code
  scanning.
- Config file support (`.mcpauditrc`) for enabling/disabling rules, severity
  overrides, ignore patterns, and the fail threshold.
- CLI with `stdio`, `http`, `static`, and `rules` commands plus CI-friendly
  exit codes.
- Hermetic mock MCP server fixture and a vitest suite covering the engine,
  individual rules, reporters, config, static mode, and a live stdio audit.
