<?php
declare(strict_types=1);
namespace SecuLens;

final class Mcp
{
    public const TOOLS = [
        [
            'name' => 'seculens_scan',
            'description' => 'Scan SPDX or CycloneDX SBOM for known vulnerabilities (OSV) and license policy violations',
            'inputSchema' => [
                'type' => 'object',
                'properties' => [
                    'sbomPath' => ['type' => 'string', 'description' => 'Path to SPDX or CycloneDX JSON file'],
                    'dbPath' => ['type' => 'string', 'description' => 'Path to local OSV JSON snapshot (optional, offline)'],
                    'fetchOsv' => ['type' => 'boolean', 'description' => 'Fetch candidate advisories from api.osv.dev if dbPath not provided (default: true)'],
                    'policy' => [
                        'type' => 'object',
                        'description' => 'License policy with allow and/or deny lists',
                        'properties' => [
                            'allow' => ['type' => 'array', 'items' => ['type' => 'string']],
                            'deny' => ['type' => 'array', 'items' => ['type' => 'string']],
                        ],
                    ],
                ],
                'required' => ['sbomPath'],
            ],
        ],
        [
            'name' => 'seculens_analyze',
            'description' => 'Perform static AST analysis and supply chain inspection on source directory and lifecycle scripts',
            'inputSchema' => [
                'type' => 'object',
                'properties' => [
                    'directory' => ['type' => 'string', 'description' => 'Directory containing source code and package files'],
                ],
                'required' => ['directory'],
            ],
        ],
        [
            'name' => 'seculens_check_license',
            'description' => 'Evaluate an SPDX license expression against allow/deny lists',
            'inputSchema' => [
                'type' => 'object',
                'properties' => [
                    'expression' => ['type' => 'string', 'description' => 'SPDX license expression (e.g. \'MIT OR Apache-2.0\')'],
                    'allow' => ['type' => 'array', 'items' => ['type' => 'string']],
                    'deny' => ['type' => 'array', 'items' => ['type' => 'string']],
                ],
                'required' => ['expression'],
            ],
        ],
        [
            'name' => 'seculens_generate_report',
            'description' => 'Generate customer Word (.docx) and JSON reports from SBOM and analysis results',
            'inputSchema' => [
                'type' => 'object',
                'properties' => [
                    'sbomPath' => ['type' => 'string', 'description' => 'Path to SBOM JSON'],
                    'outputDir' => ['type' => 'string', 'description' => 'Directory where report.docx and report.json will be saved'],
                    'customer' => ['type' => 'string', 'description' => 'Customer name'],
                    'target' => ['type' => 'string', 'description' => 'Target system name'],
                    'dbPath' => ['type' => 'string', 'description' => 'Path to local OSV JSON snapshot (optional)'],
                    'sourceDir' => ['type' => 'string', 'description' => 'Optional source directory for AST analysis'],
                    'lang' => ['type' => 'string', 'enum' => ['en', 'ja'], 'description' => 'Report language: en or ja'],
                ],
                'required' => ['sbomPath', 'outputDir'],
            ],
        ],
    ];

    public static function handleRequest(array $request): ?array
    {
        $id = $request['id'] ?? null;
        $method = $request['method'] ?? '';
        $params = $request['params'] ?? [];

        if ($method === 'initialize') {
            return [
                'jsonrpc' => '2.0',
                'id' => $id,
                'result' => [
                    'protocolVersion' => '2024-11-05',
                    'capabilities' => ['tools' => new \stdClass()],
                    'serverInfo' => ['name' => 'seculens-php', 'version' => '1.1.0'],
                ],
            ];
        }

        if ($method === 'notifications/initialized') {
            return null;
        }

        if ($method === 'ping') {
            return ['jsonrpc' => '2.0', 'id' => $id, 'result' => new \stdClass()];
        }

        if ($method === 'tools/list') {
            return ['jsonrpc' => '2.0', 'id' => $id, 'result' => ['tools' => self::TOOLS]];
        }

        if ($method === 'tools/call') {
            $name = $params['name'] ?? '';
            $args = $params['arguments'] ?? [];
            try {
                $contentText = '';
                if ($name === 'seculens_scan') {
                    $sbomRaw = file_get_contents($args['sbomPath']);
                    if ($sbomRaw === false) { throw new \RuntimeException('Cannot read sbomPath'); }
                    $sbom = Sbom::parse(json_decode($sbomRaw, true));
                    $records = [];
                    $dbSource = 'None';
                    $dbHash = '';
                    if (!empty($args['dbPath'])) {
                        $dbRaw = file_get_contents($args['dbPath']);
                        if ($dbRaw === false) { throw new \RuntimeException('Cannot read dbPath'); }
                        $records = Database::validate(json_decode($dbRaw, true));
                        $dbSource = basename($args['dbPath']);
                        $dbHash = hash('sha256', $dbRaw);
                    } elseif (!isset($args['fetchOsv']) || $args['fetchOsv']) {
                        $records = Database::fetch($sbom['components']);
                        $dbSource = 'OSV API snapshot';
                        $dbHash = hash('sha256', json_encode($records));
                    }
                    $policy = $args['policy'] ?? [];
                    $report = Assessment::scan($sbomRaw, $records, [
                        'policy' => $policy,
                        'databaseSource' => $dbSource,
                        'databaseHash' => $dbHash,
                    ]);
                    $affected = count(array_filter($report['findings'], static fn($f) => ($f['category'] ?? '') === 'vulnerability' && ($f['status'] ?? '') === 'affected'));
                    $denied = count(array_filter($report['findings'], static fn($f) => ($f['category'] ?? '') === 'license' && ($f['status'] ?? '') === 'denied'));
                    $contentText = json_encode([
                        'summary' => [
                            'components' => count($report['sbom']['components']),
                            'findings' => count($report['findings']),
                            'affectedVulnerabilities' => $affected,
                            'deniedLicenses' => $denied,
                        ],
                        'findings' => $report['findings'],
                    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                } elseif ($name === 'seculens_analyze') {
                    $res = Analysis::scan($args['directory']);
                    $findings = $res['findings'];
                    $security = count(array_filter($findings, static fn($f) => ($f['category'] ?? '') === 'security'));
                    $quality = count(array_filter($findings, static fn($f) => ($f['category'] ?? '') === 'quality'));
                    $contentText = json_encode([
                        'totalFindings' => count($findings),
                        'securityReviewCandidates' => $security,
                        'qualityFindings' => $quality,
                        'findings' => $findings,
                    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                } elseif ($name === 'seculens_check_license') {
                    $expr = $args['expression'] ?? '';
                    $policy = ['allow' => $args['allow'] ?? [], 'deny' => $args['deny'] ?? []];
                    $status = Licenses::evaluate($expr, $policy);
                    $contentText = json_encode(['expression' => $expr, 'status' => $status]);
                } elseif ($name === 'seculens_generate_report') {
                    $options = [
                        'sbom' => $args['sbomPath'],
                        'output' => $args['outputDir'],
                        'customer' => $args['customer'] ?? 'Customer',
                        'target' => $args['target'] ?? basename($args['sbomPath']),
                        'db' => $args['dbPath'] ?? null,
                        'fetch-osv' => empty($args['dbPath']),
                        'source' => $args['sourceDir'] ?? null,
                        'lang' => $args['lang'] ?? 'en',
                        'report-style' => 'customer',
                    ];
                    $res = Runner::scan($options);
                    $jsonPath = $args['outputDir'] . DIRECTORY_SEPARATOR . 'report.json';
                    $docxPath = $args['outputDir'] . DIRECTORY_SEPARATOR . 'report.docx';
                    $contentText = json_encode([
                        'status' => 'success',
                        'reportJson' => realpath($jsonPath) ?: $jsonPath,
                        'reportDocx' => realpath($docxPath) ?: $docxPath,
                        'findingsCount' => count($res['report']['findings']),
                    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                } else {
                    return [
                        'jsonrpc' => '2.0',
                        'id' => $id,
                        'error' => ['code' => -32601, 'message' => "Unknown tool: {$name}"],
                    ];
                }

                return [
                    'jsonrpc' => '2.0',
                    'id' => $id,
                    'result' => ['content' => [['type' => 'text', 'text' => $contentText]], 'isError' => false],
                ];
            } catch (\Throwable $e) {
                return [
                    'jsonrpc' => '2.0',
                    'id' => $id,
                    'result' => ['content' => [['type' => 'text', 'text' => 'Error: ' . $e->getMessage()]], 'isError' => true],
                ];
            }
        }

        return [
            'jsonrpc' => '2.0',
            'id' => $id,
            'error' => ['code' => -32601, 'message' => "Method not found: {$method}"],
        ];
    }

    public static function runServer(): void
    {
        while (($line = fgets(STDIN)) !== false) {
            $line = trim($line);
            if ($line === '') { continue; }
            $req = json_decode($line, true);
            if (!is_array($req)) {
                fwrite(STDOUT, json_encode(['jsonrpc' => '2.0', 'id' => null, 'error' => ['code' => -32700, 'message' => 'Parse error']]) . "\n");
                fflush(STDOUT);
                continue;
            }
            $res = self::handleRequest($req);
            if ($res !== null) {
                fwrite(STDOUT, json_encode($res, JSON_UNESCAPED_SLASHES) . "\n");
                fflush(STDOUT);
            }
        }
    }
}
