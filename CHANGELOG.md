# Changelog

## 1.1.0

- Add lifecycle script detection (`SC-LIFECYCLE-SCRIPT`) in `composer.json`, `package.json` and `package-lock.json`.
- Add supply-chain AST inspection rules for shell execution (`PHP-SHELL`), environment variable access (`PHP-PROCESS-ENV`), and sensitive path references (`PHP-SENSITIVE-PATH`).
- Add Model Context Protocol (MCP) stdio server (`seculens mcp`) supporting Claude Desktop, Cursor, and other AI agents.
- Add lockfile integrity verification (`SC-INTEGRITY-MISMATCH`, `SC-INSECURE-REGISTRY-URL`).
- Add transitive dependency depth calculation in SBOM parsing.
- Add weekly Dependabot automated updates and pull request dependency review workflow.

## 1.0.0

- Align the Python, JavaScript/TypeScript and PHP release versions at 1.0.0.
- Includes SPDX/CycloneDX assessment, native vulnerability matching, license policies, language-native AST review, bilingual wizard and customer Word reports.
- Includes output file safety fixes from the preceding maintenance release.

## 0.1.2

- Protect report and SBOM output from destination symlink overwrite, and restrict new report file permissions.
- Reject URL/stream wrapper paths in local JSON input and output.


## 0.1.1

Exclude development dependencies and test caches from Composer archives; interrupt blocked wizard input immediately on Ctrl+C.

## 0.1.0

Initial independent PHP implementation with SPDX/CycloneDX JSON import, local OSV version matching for npm/PyPI/Packagist, SPDX license-expression policies, PHP AST review and complexity, bilingual CLI wizard, customer/standard Word reports, embedded Japanese font, shared JSON schema 1.1, SHA-256 evidence snapshots and Syft SBOM generation.
