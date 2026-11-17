<?php
declare(strict_types=1);
namespace SecuLens;

/** Lockfile integrity verification and package release age (cool-off) inspection. */
final class Integrity
{
    public const COOL_OFF_MAX_DAYS = 3650;
    private const COOL_OFF_ECOSYSTEMS = ['npm', 'PyPI', 'Packagist'];
    private const TIMESTAMP = '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/i';
    private const JSON_FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;

    /** Checks package-lock.json and composer.lock in $directory; missing or unparseable lockfiles are skipped. */
    public static function checkLockfileIntegrity(string $directory, array $sbom): array
    {
        $root = realpath($directory);
        if ($root === false) { return []; }
        $findings = [];

        $npmLock = self::readLock($root.DIRECTORY_SEPARATOR.'package-lock.json');
        if ($npmLock !== null) {
            $sbomHashes = [];
            foreach ($sbom['components'] ?? [] as $c) {
                if (($c['name'] ?? '') !== '' && !empty($c['hashes'])) { $sbomHashes[$c['name'].'@'.($c['version'] ?? '')] = $c['hashes']; }
            }
            $packages = is_array($npmLock['packages'] ?? null) && !array_is_list($npmLock['packages']) ? $npmLock['packages'] : [];
            foreach ($packages as $pkgKey => $pkgVal) {
                $pkgKey = (string)$pkgKey;
                if ($pkgKey === '' || !is_array($pkgVal) || ($pkgVal !== [] && array_is_list($pkgVal))) { continue; }
                $parts = explode('node_modules/', $pkgKey);
                $pkgName = end($parts);
                $version = is_string($pkgVal['version'] ?? null) ? $pkgVal['version'] : '';
                $resolved = $pkgVal['resolved'] ?? null;
                $integrity = $pkgVal['integrity'] ?? null;

                if (is_string($resolved) && str_starts_with($resolved, 'http://')) {
                    $findings[] = [
                        'category' => 'security', 'ruleId' => 'SC-INSECURE-REGISTRY-URL', 'subject' => $pkgName, 'status' => 'review',
                        'summary' => "Insecure HTTP package resolution URL: {$pkgName}",
                        'evidence' => "resolved: \"{$resolved}\"",
                        'recommendation' => 'Replace HTTP package sources with secure HTTPS registries to prevent man-in-the-middle attacks.',
                        'file' => 'package-lock.json',
                    ];
                }

                $hashes = $sbomHashes["$pkgName@$version"] ?? null;
                if ($hashes === null || !is_string($integrity) || !str_contains($integrity, '-')) { continue; }
                [$alg, $value] = explode('-', $integrity, 2);
                $matched = false;
                foreach ($hashes as $h) {
                    $content = (string)($h['content'] ?? '');
                    if (self::normalizeAlg((string)($h['alg'] ?? '')) === strtolower($alg) && ($content === $value || self::base64Digest($content) === $value)) { $matched = true; break; }
                }
                if (!$matched) {
                    $listed = array_map(static fn(array $h): array => ['alg' => (string)($h['alg'] ?? ''), 'content' => (string)($h['content'] ?? '')], $hashes);
                    $findings[] = [
                        'category' => 'security', 'ruleId' => 'SC-INTEGRITY-MISMATCH', 'subject' => $pkgName, 'status' => 'review',
                        'summary' => "Lockfile integrity hash mismatch for {$pkgName}@{$version}",
                        'evidence' => "lockfile: \"{$integrity}\"; SBOM hashes: ".json_encode($listed, self::JSON_FLAGS),
                        'recommendation' => 'Investigate possible package tampering or lockfile poisoning before installing or deploying.',
                        'file' => 'package-lock.json',
                    ];
                }
            }
        }

        $composerLock = self::readLock($root.DIRECTORY_SEPARATOR.'composer.lock');
        if ($composerLock !== null) {
            $list = static fn(mixed $v): array => is_array($v) && array_is_list($v) ? $v : [];
            foreach ([...$list($composerLock['packages'] ?? null), ...$list($composerLock['packages-dev'] ?? null)] as $p) {
                if (!is_array($p) || ($p !== [] && array_is_list($p))) { continue; }
                $name = is_string($p['name'] ?? null) ? $p['name'] : '';
                $distUrl = is_array($p['dist'] ?? null) ? ($p['dist']['url'] ?? null) : null;
                if (is_string($distUrl) && str_starts_with($distUrl, 'http://')) {
                    $findings[] = [
                        'category' => 'security', 'ruleId' => 'SC-INSECURE-REGISTRY-URL', 'subject' => $name, 'status' => 'review',
                        'summary' => "Insecure HTTP download URL in composer.lock: {$name}",
                        'evidence' => "dist.url: \"{$distUrl}\"",
                        'recommendation' => 'Use secure HTTPS package sources to avoid tampering during download.',
                        'file' => 'composer.lock',
                    ];
                }
            }
        }

        return $findings;
    }

    /** Accepts a whole number of days from 1 to 3650, given as an integer or a string of digits. */
    public static function parseCoolOffDays(mixed $value): int
    {
        $text = match (true) {
            is_int($value) => (string)$value,
            is_float($value) && floor($value) === $value && is_finite($value) => sprintf('%.0f', $value),
            is_string($value) => $value,
            default => '',
        };
        $days = preg_match('/^[0-9]+$/D', $text) === 1 && strlen($text) <= 6 ? (int)$text : 0;
        if ($days < 1 || $days > self::COOL_OFF_MAX_DAYS) {
            throw new \InvalidArgumentException('Cool-off must be a whole number of days from 1 to '.self::COOL_OFF_MAX_DAYS);
        }
        return $days;
    }

    /** Pure cool-off evaluation: one finding per npm, PyPI or Packagist release younger than $minDays. */
    public static function coolOffFindings(array $components, array $published, int $minDays, \DateTimeInterface $now): array
    {
        $nowMs = self::milliseconds($now);
        $findings = [];
        foreach (self::coolOffTargets($components) as $c) {
            $timeStr = $published[$c['ecosystem']][$c['name'].'@'.$c['version']] ?? null;
            $ms = is_string($timeStr) ? self::timestampMs($timeStr) : null;
            if ($ms === null) { continue; }
            if ($nowMs < $ms) { continue; }
            $days = intdiv($nowMs - $ms, 86_400_000);
            if ($days >= $minDays) { continue; }
            $findings[] = [
                'category' => 'security', 'ruleId' => 'SC-PACKAGE-AGE-UNVERIFIED', 'subject' => $c['name'].'@'.$c['version'], 'status' => 'review',
                'summary' => "Package version was released recently ({$days} day(s) ago)",
                'evidence' => "Published on {$timeStr} ({$days} days ago; cool-off threshold={$minDays} days)",
                'recommendation' => 'Allow a cool-off period before upgrading in production to guard against compromised zero-day releases.',
            ];
        }
        return $findings;
    }

    /** Expands Packagist's minified p2 version list, where each entry only lists fields that changed. */
    public static function expandPackagistVersions(mixed $versions): array
    {
        $expanded = []; $previous = [];
        foreach (is_array($versions) && array_is_list($versions) ? $versions : [] as $entry) {
            if (!is_array($entry) || ($entry !== [] && array_is_list($entry))) { continue; }
            $current = $previous;
            foreach ($entry as $key => $value) {
                if ($value === '__unset') { unset($current[$key]); } else { $current[$key] = $value; }
            }
            $expanded[] = $current; $previous = $current;
        }
        return $expanded;
    }

    /**
     * Looks up release timestamps from registry.npmjs.org, pypi.org and repo.packagist.org.
     * Sends package names and versions only. Failed lookups are left out, so those components are not flagged.
     */
    public static function fetchReleaseDates(array $components, ?callable $getJson = null): array
    {
        $getJson ??= self::getJson(...);
        $dates = ['npm' => [], 'PyPI' => [], 'Packagist' => []];
        $documents = [];
        $once = static function (string $url) use (&$documents, $getJson): mixed {
            if (!array_key_exists($url, $documents)) { $documents[$url] = $getJson($url); }
            return $documents[$url];
        };
        foreach (self::coolOffTargets($components) as $c) {
            [$name, $version, $ecosystem] = [$c['name'], $c['version'], $c['ecosystem']];
            $time = null;
            if ($ecosystem === 'npm') {
                $pos = strpos($name, '/');
                $doc = $once('https://registry.npmjs.org/'.($pos === false ? $name : substr_replace($name, '%2F', $pos, 1)));
                $time = is_array($doc) && is_array($doc['time'] ?? null) ? ($doc['time'][$version] ?? null) : null;
            } elseif ($ecosystem === 'PyPI') {
                $doc = $once('https://pypi.org/pypi/'.rawurlencode($name).'/'.rawurlencode($version).'/json');
                $uploads = [];
                foreach (is_array($doc) && is_array($doc['urls'] ?? null) ? $doc['urls'] : [] as $u) {
                    if (is_array($u) && is_string($u['upload_time_iso_8601'] ?? null)) { $uploads[] = $u['upload_time_iso_8601']; }
                }
                sort($uploads, SORT_STRING);
                $time = $uploads[0] ?? null;
            } elseif (preg_match('~^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$~D', $name) === 1) {
                $key = strtolower($name);
                $doc = $once("https://repo.packagist.org/p2/$key.json");
                $strip = static fn(string $v): string => preg_replace('/^v/i', '', $v);
                foreach (self::expandPackagistVersions(is_array($doc) ? ($doc['packages'][$key] ?? null) : null) as $entry) {
                    if (is_string($entry['version'] ?? null) && $strip($entry['version']) === $strip($version)) { $time = $entry['time'] ?? null; break; }
                }
            }
            if (is_string($time)) { $dates[$ecosystem]["$name@$version"] = $time; }
        }
        return $dates;
    }

    /** Flags npm, PyPI and Packagist releases younger than $minDays. */
    public static function checkPackageCoolOff(array $components, int $minDays = 7, ?\DateTimeInterface $now = null, ?callable $lookup = null): array
    {
        $lookup ??= self::fetchReleaseDates(...);
        return self::coolOffFindings($components, $lookup($components), $minDays, $now ?? new \DateTimeImmutable('now', new \DateTimeZone('UTC')));
    }

    private static function readLock(string $path): ?array
    {
        if (!is_file($path)) { return null; }
        $text = @file_get_contents($path);
        if ($text === false) { return null; }
        try { $value = json_decode($text, true, 512, JSON_THROW_ON_ERROR); } catch (\JsonException) { return null; }
        return is_array($value) && ($value === [] || !array_is_list($value)) ? $value : null;
    }

    /** Hex digests are compared as base64, the encoding npm uses; anything else is compared as written. */
    private static function base64Digest(string $content): string
    {
        return preg_match('/^(?:[0-9a-f]{2})+$/iD', $content) === 1 ? base64_encode((string)hex2bin($content)) : $content;
    }

    private static function normalizeAlg(string $alg): string { return str_replace(['-', '_'], '', strtolower($alg)); }

    private static function coolOffTargets(array $components): array
    {
        $seen = []; $targets = [];
        foreach ($components as $c) {
            if (!is_string($c['name'] ?? null) || $c['name'] === '' || !is_string($c['version'] ?? null) || $c['version'] === '' || !in_array($c['ecosystem'] ?? null, self::COOL_OFF_ECOSYSTEMS, true)) { continue; }
            $key = $c['ecosystem'].'|'.$c['name'].'@'.$c['version'];
            if (isset($seen[$key])) { continue; }
            $seen[$key] = true; $targets[] = $c;
        }
        return $targets;
    }

    private static function timestampMs(string $text): ?int
    {
        if (preg_match(self::TIMESTAMP, $text) !== 1) { return null; }
        // Millisecond precision, matching the TypeScript and Python implementations.
        try { return self::milliseconds(new \DateTimeImmutable(preg_replace('/(\.\d{3})\d+/', '$1', $text))); }
        catch (\Exception) { return null; }
    }

    private static function milliseconds(\DateTimeInterface $time): int
    {
        return (int)$time->format('U') * 1000 + intdiv((int)$time->format('u'), 1000);
    }

    private static function getJson(string $url): mixed
    {
        $ch = curl_init($url);
        if ($ch === false) { return null; }
        curl_setopt_array($ch, [CURLOPT_HTTPHEADER => ['Accept: application/json', 'User-Agent: SecuLens'], CURLOPT_RETURNTRANSFER => true, CURLOPT_CONNECTTIMEOUT => 10, CURLOPT_TIMEOUT => 10, CURLOPT_FOLLOWLOCATION => false, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS]);
        $text = curl_exec($ch); $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if (!is_string($text) || $status < 200 || $status >= 300) { return null; }
        try { return json_decode($text, true, 512, JSON_THROW_ON_ERROR); } catch (\JsonException) { return null; }
    }
}
