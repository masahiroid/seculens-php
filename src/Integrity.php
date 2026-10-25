<?php
declare(strict_types=1);
namespace SecuLens;

final class Integrity
{
    public static function checkLockfileIntegrity(string $directory, array $sbom): array
    {
        $root = realpath($directory);
        if ($root === false) { return []; }
        $findings = [];

        // 1. package-lock.json
        $npmLock = $root . DIRECTORY_SEPARATOR . 'package-lock.json';
        if (is_file($npmLock)) {
            try {
                $raw = file_get_contents($npmLock);
                $lock = json_decode($raw ?: '', true);
                $packages = $lock['packages'] ?? [];
                $sbomHashes = [];
                foreach ($sbom['components'] ?? [] as $c) {
                    $name = $c['name'] ?? '';
                    $ver = $c['version'] ?? '';
                    if ($name !== '' && !empty($c['hashes'])) {
                        $sbomHashes["$name@$ver"] = $c['hashes'];
                    }
                }

                foreach ($packages as $pkgKey => $pkgVal) {
                    if ($pkgKey === '' || !is_array($pkgVal)) { continue; }
                    $parts = explode('node_modules/', (string)$pkgKey);
                    $pkgName = end($parts);
                    $version = $pkgVal['version'] ?? '';
                    $resolved = $pkgVal['resolved'] ?? '';
                    $integrity = $pkgVal['integrity'] ?? '';

                    if (is_string($resolved) && str_starts_with($resolved, 'http://')) {
                        $findings[] = [
                            'category' => 'security',
                            'ruleId' => 'SC-INSECURE-REGISTRY-URL',
                            'subject' => $pkgName,
                            'status' => 'review',
                            'summary' => "Insecure HTTP package resolution URL: {$pkgName}",
                            'evidence' => "resolved: \"{$resolved}\"",
                            'recommendation' => 'Replace HTTP package sources with secure HTTPS registries to prevent man-in-the-middle attacks.',
                            'file' => 'package-lock.json',
                            'line' => 1,
                        ];
                    }

                    $key = "$pkgName@$version";
                    if (isset($sbomHashes[$key]) && is_string($integrity) && str_contains($integrity, '-')) {
                        [$alg, $val] = explode('-', $integrity, 2);
                        $matched = false;
                        foreach ($sbomHashes[$key] as $h) {
                            $hAlg = strtolower(str_replace(['-', '_'], '', $h['alg'] ?? ''));
                            $hContent = $h['content'] ?? '';
                            if ($hAlg === strtolower($alg)) {
                                $hB64 = ctype_xdigit($hContent) ? base64_encode(hex2bin($hContent)) : $hContent;
                                if ($hContent === $val || $hB64 === $val) {
                                    $matched = true;
                                    break;
                                }
                            }
                        }
                        if (!$matched && !empty($sbomHashes[$key])) {
                            $findings[] = [
                                'category' => 'security',
                                'ruleId' => 'SC-INTEGRITY-MISMATCH',
                                'subject' => $pkgName,
                                'status' => 'review',
                                'summary' => "Lockfile integrity hash mismatch for {$pkgName}@{$version}",
                                'evidence' => "lockfile: \"{$integrity}\"; SBOM hashes: " . json_encode($sbomHashes[$key]),
                                'recommendation' => 'Investigate possible package tampering or lockfile poisoning before installing or deploying.',
                                'file' => 'package-lock.json',
                                'line' => 1,
                            ];
                        }
                    }
                }
            } catch (\Throwable) {}
        }

        // 2. composer.lock
        $composerLock = $root . DIRECTORY_SEPARATOR . 'composer.lock';
        if (is_file($composerLock)) {
            try {
                $raw = file_get_contents($composerLock);
                $lock = json_decode($raw ?: '', true);
                $pkgs = array_merge($lock['packages'] ?? [], $lock['packages-dev'] ?? []);
                foreach ($pkgs as $p) {
                    if (!is_array($p)) { continue; }
                    $name = $p['name'] ?? '';
                    $distUrl = $p['dist']['url'] ?? '';
                    if (is_string($distUrl) && str_starts_with($distUrl, 'http://')) {
                        $findings[] = [
                            'category' => 'security',
                            'ruleId' => 'SC-INSECURE-REGISTRY-URL',
                            'subject' => $name,
                            'status' => 'review',
                            'summary' => "Insecure HTTP download URL in composer.lock: {$name}",
                            'evidence' => "dist.url: \"{$distUrl}\"",
                            'recommendation' => 'Use secure HTTPS package sources to avoid tampering during download.',
                            'file' => 'composer.lock',
                            'line' => 1,
                        ];
                    }
                }
            } catch (\Throwable) {}
        }

        return $findings;
    }
}

