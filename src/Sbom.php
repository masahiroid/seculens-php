<?php
declare(strict_types=1);
namespace SecuLens;

final class Sbom
{
    public static function identity(?string $purl): array
    {
        if ($purl === null || !preg_match('~^pkg:([a-z][a-z0-9.+-]*)/([^?#]+)(?:\?[^#]+)?(?:#.+)?$~', $purl, $m)) {
            return [];
        }
        if (preg_match('/%(?![0-9a-fA-F]{2})/', $purl)) { return []; }
        $parts = explode('@', $m[2]);
        if (count($parts) > 2) { return []; }
        $path = rawurldecode($parts[0]);
        $version = isset($parts[1]) ? rawurldecode($parts[1]) : null;
        $type = $m[1];
        if ($path === '' || preg_match('/[\s\x00-\x1f?#]/u', $path) || $version === '') { return []; }
        $valid = match ($type) {
            'npm' => (bool) preg_match('~^(?:@[^/]+/)?[^/@]+$~', $path),
            'pypi' => (bool) preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]*$/', $path),
            'composer' => (bool) preg_match('~^[a-z0-9_.-]+/[a-z0-9_.-]+$~', $path),
            default => false,
        };
        if (!$valid) { return []; }
        $result = ['name' => $type === 'pypi' ? strtolower($path) : $path, 'ecosystem' => ['npm' => 'npm', 'pypi' => 'PyPI', 'composer' => 'Packagist'][$type]];
        if ($version !== null) { $result['version'] = $version; }
        return $result;
    }

    public static function parse(mixed $input): array
    {
        $d = Json::object($input, 'SBOM must be a JSON object');
        $components = []; $dependencies = []; $warnings = [];
        if (($d['bomFormat'] ?? null) === 'CycloneDX') {
            $format = 'CycloneDX'; $version = $d['specVersion'] ?? '';
            if (!in_array($version, ['1.4', '1.5', '1.6', '1.7'], true)) { throw new \InvalidArgumentException('Unsupported CycloneDX version'); }
            $collect = function (array $items, string $prefix, int $depth = 0) use (&$collect, &$components): void {
                if ($depth > 64) { throw new \InvalidArgumentException('SBOM nesting too deep'); }
                foreach ($items as $i => $item) {
                    $c = Json::object($item, 'Invalid component');
                    if (!Json::text($c['name'] ?? null)) { throw new \InvalidArgumentException('Component name required'); }
                    $licenses = [];
                    foreach (Json::list($c['licenses'] ?? [], 'Invalid component licenses') as $l) {
                        $l = Json::object($l, 'Invalid license');
                        $value = $l['expression'] ?? $l['license']['id'] ?? $l['license']['name'] ?? null;
                        if (Json::text($value)) { $licenses[] = $value; }
                    }
                    $components[] = self::component($c['bom-ref'] ?? "$prefix$i", isset($c['group']) ? $c['group'].'/'.$c['name'] : $c['name'], $c['version'] ?? null, $c['purl'] ?? null, $licenses);
                    $collect(Json::list($c['components'] ?? [], 'Invalid nested components'), "$prefix$i/", $depth + 1);
                }
            };
            $collect(Json::list($d['components'] ?? [], 'CycloneDX components must be an array'), 'component-');
            foreach (Json::list($d['dependencies'] ?? [], 'Invalid dependencies') as $e) {
                $e = Json::object($e, 'Invalid dependency');
                foreach (Json::list($e['dependsOn'] ?? [], 'Invalid dependsOn') as $to) { $dependencies[] = ['from' => $e['ref'] ?? null, 'to' => $to]; }
            }
        } elseif (isset($d['spdxVersion'])) {
            $format = 'SPDX'; $version = $d['spdxVersion'];
            if (!in_array($version, ['SPDX-2.2', 'SPDX-2.3'], true)) { throw new \InvalidArgumentException('Unsupported SPDX version'); }
            foreach (Json::list($d['packages'] ?? null, 'SPDX packages must be an array') as $i => $p) {
                $p = Json::object($p, 'Invalid package');
                if (!Json::text($p['name'] ?? null)) { throw new \InvalidArgumentException('Package name required'); }
                $purl = null;
                foreach (Json::list($p['externalRefs'] ?? [], 'Invalid externalRefs') as $ref) {
                    if (($ref['referenceType'] ?? null) === 'purl') { $purl = $ref['referenceLocator'] ?? null; break; }
                }
                $license = ($p['licenseConcluded'] ?? 'NOASSERTION') !== 'NOASSERTION' ? $p['licenseConcluded'] : ($p['licenseDeclared'] ?? 'NOASSERTION');
                $components[] = self::component($p['SPDXID'] ?? "package-$i", $p['name'], $p['versionInfo'] ?? null, $purl, Json::text($license) ? [$license] : []);
            }
            foreach (Json::list($d['relationships'] ?? [], 'Invalid relationships') as $e) {
                if (($e['relationshipType'] ?? null) === 'DEPENDS_ON') { $dependencies[] = ['from' => $e['spdxElementId'] ?? null, 'to' => $e['relatedSpdxElement'] ?? null]; }
                if (($e['relationshipType'] ?? null) === 'DEPENDENCY_OF') { $dependencies[] = ['from' => $e['relatedSpdxElement'] ?? null, 'to' => $e['spdxElementId'] ?? null]; }
            }
        } else { throw new \InvalidArgumentException('Expected SPDX JSON or CycloneDX JSON'); }
        $ids = [];
        foreach ($components as $c) {
            if (isset($ids[$c['id']])) { throw new \InvalidArgumentException('Duplicate component ID: '.$c['id']); }
            $ids[$c['id']] = true;
            if (isset($c['purl']) && self::identity($c['purl']) === []) { $warnings[] = 'Invalid or unsupported purl: '.$c['id']; }
        }
        foreach ($dependencies as $e) {
            if (!Json::text($e['from']) || !Json::text($e['to'])) { throw new \InvalidArgumentException('Invalid dependency endpoints'); }
            if (!isset($ids[$e['from']], $ids[$e['to']])) { $warnings[] = "Dependency endpoint not in component list: {$e['from']} -> {$e['to']}"; }
        }
        return compact('format', 'version', 'components', 'dependencies', 'warnings');
    }
    private static function component(mixed $id, string $name, mixed $version, mixed $purl, array $licenses): array
    {
        if (!Json::text($id) || ($version !== null && !Json::text($version)) || ($purl !== null && !is_string($purl))) { throw new \InvalidArgumentException('Invalid component identity'); }
        $c = ['id' => $id, 'name' => $name, 'licenses' => $licenses];
        if ($version !== null) { $c['version'] = $version; }
        if ($purl !== null) { $c['purl'] = $purl; }
        return array_replace($c, self::identity($purl));
    }
}
