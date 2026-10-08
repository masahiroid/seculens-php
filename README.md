# SecuLens for PHP

[English](README.md) | [日本語](README.jp.md)

Independent native PHP security assessment CLI and library. Import SPDX or CycloneDX JSON SBOMs, match dependency versions against OSV advisory snapshots, evaluate SPDX license policies, review PHP syntax trees and generate customer-facing Word and JSON reports. PHP 8.2+; no Python, Node.js or Trivy runtime is needed.

**0.1.0 is an initial release.** Matches are evidence from the supplied snapshot; AST findings are review candidates. Full SAST, exploitability and legal compliance determinations are outside this release. The [Python](https://github.com/masahiroid/seculens-python) and [JS/TypeScript](https://github.com/masahiroid/seculens) implementations share the JSON report schema.

## Installation

Requires PHP 8.2 or later, Composer 2 and PHP extensions `curl`, `dom`, `mbstring`, `xml` and `zip` (plus dependencies' requirements).

Until Packagist registration is complete, install from the repository:

```sh
git clone https://github.com/masahiroid/seculens-php.git
cd seculens-php
composer install --no-dev
php bin/seculens
```

A source archive is also available from [GitHub Releases](https://github.com/masahiroid/seculens-php/releases). Extract it, run `composer install --no-dev` inside it and use `php bin/seculens`. Dependencies are not bundled.

After Packagist registration, the planned Composer command is:

```sh
composer require --dev masahiroid/seculens
vendor/bin/seculens
```

That command requires the package to be registered on Packagist first. A CLI installed through Composer is named `seculens`; the Composer package identifier includes its required vendor prefix. See [publishing instructions](docs/publishing.md).

## Interactive wizard

Run `seculens` with no arguments, or `php bin/seculens` from the source checkout. English is the default; enter `ja` at the language prompt for Japanese. To start directly in Japanese:

```sh
php bin/seculens wizard --lang ja
```

Choose SBOM assessment or generation. Assessment collects the SBOM, local database or explicit OSV download, optional license policy and PHP source, customer/target/preparer, report style, output directory and findings exit policy. Customer layout is the wizard default. Review the settings and confirm before execution. EOF or declining confirmation cancels without starting; Ctrl+C exits 130 on platforms with `pcntl`. Relative paths are based on the current working directory.

## Assess an existing SBOM

Offline assessment using a local OSV snapshot:

```sh
php bin/seculens scan bom.json --db database.json --policy policy.json \
  --source ./src --customer "Customer Company" --target "Customer Web Service" \
  --issuer "Assessment Team" --lang ja --report-style customer --output reports/customer
```

Use the repository's synthetic examples:

```sh
php bin/seculens scan examples/cyclonedx.json --db examples/database.json \
  --policy examples/policy.json --source examples --report-style customer --output reports/demo
```

**Example advisories are fabricated demonstration records, not a production database.** Output contains `report.docx`, `report.json`, the original `sbom.json` and `database.json`. SHA-256 hashes identify the exact SBOM and database text. Reusing a snapshot stabilizes assessment results; timestamps and generated DOCX metadata can differ.

To download candidate advisories explicitly:

```sh
php bin/seculens scan bom.json --fetch-osv --output reports/live
```

`--fetch-osv` sends package names and ecosystems to `api.osv.dev`. Matching is performed locally. Source code, versions and the entire SBOM are not uploaded. The wizard discloses this before execution. Fetching requires network access; HTTP failures or malformed responses stop the assessment. `--db` assessment does not use the network. Choose exactly one of `--db` and `--fetch-osv`.

## Generate SBOMs

Install [Syft](https://github.com/anchore/syft) separately:

```sh
php bin/seculens sbom ./project --format cyclonedx --output bom.cdx.json
php bin/seculens sbom ./project --format spdx --output bom.spdx.json
```

Use `--syft /path/to/syft` to select an executable. SecuLens invokes Syft with separate process arguments and validates the supported output fields. It does not install or execute the scanned project's code. Existing SBOMs from other tools can be imported directly. Syft's inventory can include Composer dependencies; the vulnerability and license assessments are implemented in PHP inside SecuLens.

## Supported input and matching

- SPDX 2.2/2.3 JSON package records and dependency relationships.
- CycloneDX 1.4–1.7 JSON components, nested components and dependency relationships.
- Package URLs `pkg:npm`, `pkg:pypi` and `pkg:composer` with versions.
- npm SemVer precedence; PyPI PEP 440 precedence and normalized names.
- Packagist stable numeric SemVer-compatible versions, leading `v`, four-part versions ending in `.0` and SemVer prereleases. Branches, branch aliases and other Composer-specific syntax remain unassessed.
- OSV explicit versions, `SEMVER`/`ECOSYSTEM` intervals, fixed/last-affected/limit boundaries, withdrawn records, pagination and advisory alias consolidation per component.

Malformed, unsupported or incomplete ranges are recorded as unassessed, rather than treated as a clean result. GIT-only ranges, other ecosystems, SPDX 3 and XML are not supported. Input checks cover fields used by SecuLens, not full standards conformance. Database completeness and vulnerable-code reachability cannot be established from an SBOM. **No match means no matching record in the supplied snapshot, not absence of vulnerabilities.**

## License policy

```json
{
  "allow": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"],
  "deny": ["AGPL-3.0-only", "AGPL-3.0-or-later"]
}
```

SPDX expressions are parsed with `AND`, `OR`, parentheses and `WITH` exceptions. `AND` requires all branches to be allowed; `OR` accepts an allowed choice. Exceptions require a complete expression entry. Deny takes precedence for the same leaf. Unknown, custom or missing licenses require review. Without a policy, licenses require review. Declared license accuracy, source licensing, distribution obligations and regulatory compliance are not verified.

## PHP AST review

`--source` parses `.php` files using [nikic/PHP-Parser](https://github.com/nikic/PHP-Parser), without importing or executing them. Rules flag:

- `eval`, shell execution functions and backticks.
- `unserialize`, nonliteral include/require paths, `md5`/`sha1` uses needing security-context review.
- Concatenated or interpolated arguments to `query`/`exec` method calls; receiver types are not resolved.
- Functions above cyclomatic complexity 10 or control nesting depth 4. Boolean operators, coalescing, cases, match arms and ternaries contribute to complexity. Nested functions are measured separately.

Imports of functions are recognized syntactically. Namespace fallback, shadowing, variable calls, data flow and receiver types are not fully resolved. Rules can miss unsafe code or produce candidates requiring manual review. Hash uses are not automatically insecure in nonsecurity contexts. Syntax errors and an explicitly requested source tree with no PHP files are coverage findings. Vendor, dependency/build directories and symlinks are skipped.

## Word report modes

`--report-style customer` produces a dedicated cover, executive summary, severity colors, numbered findings register/details, component coverage table, evidence hashes and footer page numbers. Direct scans default to `standard`; the wizard defaults to `customer`.

`--customer`, `--target` and `--issuer` fill customer, target and preparer. Target defaults to the SBOM filename. `--lang en` is the default; `--lang ja` translates principal headings, overview, built-in review summaries and recommendations. Advisory content and technical evidence retain their original language.

Critical/High are red, Medium amber, Low blue, None green and Unrated gray. Labels supplement colors. Severity derives from validated CVSS 3.0/3.1 base vectors or recognized OSV database labels. Applicable `affected.severity` overrides top-level vectors. Alias consolidation retains provenance and displays the highest supported severity. CVSS 2/4 and malformed vectors are preserved but not scored; absent other usable evidence they remain Unrated. Severity is not inferred from prose, code candidates or licenses; CVSS 0/None does not mean absence of vulnerabilities.

Japanese DOCX embeds Noto Sans JP (SIL OFL 1.1), adding approximately 4 MB. Report layout was checked using LibreOffice rendering; final pagination may vary with the Word viewer. Original metadata, field paths and references remain in report JSON schema `1.1`, compatible with the other implementations. PHP `sourceAnalysis` also records discovered/parsed file counts.

## Exit codes

- `0`: assessment completed without incomplete coverage; findings may still exist.
- `1`: `--fail-on-findings` and a vulnerability, denied license or security candidate exists.
- `2`: invalid input, operational failure or incomplete coverage. When enabled, findings status 1 takes precedence over incomplete coverage.
- `130`: Ctrl+C interruption on platforms supporting `pcntl`.

## Library API

```php
use SecuLens\Assessment;
use SecuLens\Database;
use SecuLens\Json;
use SecuLens\WordReport;

$records = Database::validate(Json::decode(file_get_contents('database.json')));
$report = Assessment::scan(file_get_contents('bom.json'), $records, [
    'customer' => 'Customer Company',
    'target' => 'Web Service',
    'policy' => ['allow' => ['MIT', 'Apache-2.0']],
]);
WordReport::write($report, 'report.docx', 'ja', 'customer', 'Assessment Team');
```

Use `SecuLens\Analysis::scan($source)` for PHP review; it returns `findings` and `metadata`. `SecuLens\Runner::scan($options)` orchestrates complete CLI-style assessment and output.

## Development

```sh
composer install
composer validate --strict
composer lint
composer test
composer audit
```

See [architecture](docs/architecture.md) and [security policy](SECURITY.md). Apache-2.0 code; bundled font is SIL OFL 1.1. [NOTICE](NOTICE) lists third-party assets. Advisory records retain their source licensing. SecuLens is independent of Trivy and the optical lens company using the SECULENS name.
