# Architecture

SecuLens for PHP is a separate implementation. It does not invoke the Python or TypeScript implementations or Trivy. PHP libraries supply syntax parsing, SPDX identifiers, console handling and DOCX serialization; SecuLens implements assessment decisions and reporting.

- `Sbom`: supported SPDX/CycloneDX adapters, package identities and dependency warnings.
- `Versions` / `Matcher`: ecosystem precedence and OSV range evaluation, with explicit unknown outcomes.
- `Database`: snapshot validation and opt-in OSV candidate fetching, pagination and deduplication.
- `Licenses`: parsed expression trees and allow/deny/review policy decisions.
- `Severity`: validated CVSS 3 base scores, database labels, applicable overrides and provenance.
- `Assessment`: schema 1.1 report contract, hashes, component checks and alias consolidation.
- `Analysis`: PHP syntax trees and independent function complexity; no analyzed code execution.
- `WordReport` / `FontEmbedder`: customer/standard reports and bundled Japanese font embedding.
- `Runner`, `Cli`, `Wizard`: file output, console commands and explicit confirmation/EOF handling.
- `Generator`: separately installed Syft, invoked as an argument array.

All original SBOM/database text is retained. Report IDs include their hashes and the assessment time. Unsupported identities, invalid ranges, syntax errors and missing source coverage remain visible; a lack of matches is never presented as proof of safety.

The initial implementation intentionally limits Composer version syntax to stable numeric SemVer-compatible values and SemVer prereleases. Full Composer branch/alias handling, interprocedural dataflow, framework-aware sources/sinks, source license discovery, container/OS vulnerability matching and customer-specific business-risk prioritization are future work.

Validation includes unit/integration tests, native Composer installation, actual Syft generation in both formats and bilingual report rendering. An external development check compared 1,451 version pairs and all 2,592 CVSS 3.1 base metric combinations with the independent Python implementation; shared sample assessment JSON agreed except tool version.
