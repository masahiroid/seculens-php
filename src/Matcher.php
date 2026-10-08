<?php
declare(strict_types=1);
namespace SecuLens;

final class Matcher
{
    public static function samePackage(array $c, array $p): bool
    {
        $ecosystem = $c['ecosystem'] ?? null;
        $normalize = static fn(string $name): string => $ecosystem === 'PyPI' ? preg_replace('/[-_.]+/', '-', strtolower($name)) : $name;
        return $ecosystem !== null && $ecosystem === $p['ecosystem'] && $normalize($c['name']) === $normalize($p['name']);
    }
    public static function supported(array $c): bool
    {
        return isset($c['ecosystem'], $c['version']) && Versions::compare($c['version'], $c['version'], $c['ecosystem']) !== null;
    }
    public static function match(array $c, array $record): string
    {
        if (!empty($record['withdrawn'])) { return 'not-affected'; }
        if (!self::supported($c)) { return 'unknown'; }
        $unknown = false; $v = $c['version']; $eco = $c['ecosystem'];
        foreach ($record['affected'] as $a) {
            if (!self::samePackage($c, $a['package'])) { continue; }
            foreach ($a['versions'] ?? [] as $explicit) { if ($v === $explicit || Versions::compare($v, $explicit, $eco) === 0) { return 'affected'; } }
            $ranges = $a['ranges'] ?? [];
            $supportedRange = array_filter($ranges, static fn(array $r): bool => in_array($r['type'], ['SEMVER','ECOSYSTEM'], true));
            foreach ($ranges as $range) {
                if (!in_array($range['type'], ['SEMVER','ECOSYSTEM'], true)) { $unknown |= !$supportedRange; continue; }
                $active = false; $uncertain = false; $opened = false; $last = null;
                // Validate the full event stream before accepting an affected interval.
                if ($range['events'] === []) { $unknown = true; continue; }
                foreach ($range['events'] as $i => $event) {
                    $kind = array_key_first($event); $boundary = $event[$kind];
                    if ($kind === 'introduced') {
                        if ($opened || ($boundary === '0' && $i !== 0)) { $uncertain = true; }
                        $opened = true;
                    } else {
                        if (!$opened) { $uncertain = true; }
                        $opened = false;
                    }
                    if (!($kind === 'introduced' && $boundary === '0')) {
                        if (Versions::compare($boundary, $boundary, $eco) === null) { $uncertain = true; }
                        if ($last !== null && (($order = Versions::compare($boundary, $last, $eco)) === null || $order < 0)) { $uncertain = true; }
                        $last = $boundary;
                    }
                }
                if ($uncertain) { $unknown = true; continue; }
                $opened = false; $last = null;
                foreach ($range['events'] as $e) {
                    $kind = array_key_first($e); $boundary = $e[$kind];
                    if ($boundary !== '0' || $kind !== 'introduced') {
                        $order = $last === null ? 0 : Versions::compare($boundary, $last, $eco);
                        if ($order === null || $order < 0) { $uncertain = true; }
                        $last = $boundary;
                    }
                    if ($kind === 'introduced') {
                        if ($opened) { $uncertain = true; }
                        $opened = true;
                        $n = $boundary === '0' ? 1 : Versions::compare($v, $boundary, $eco);
                        if ($n === null) { $uncertain = true; } else { $active = $n >= 0; }
                    } else {
                        if (!$opened) { $uncertain = true; }
                        $opened = false;
                        $n = Versions::compare($v, $boundary, $eco);
                        if ($n === null) { $uncertain = true; continue; }
                        if ($active && ($kind === 'last_affected' ? $n <= 0 : $n < 0)) { return $uncertain ? 'unknown' : 'affected'; }
                        $active = false;
                    }
                }
                if ($active && !$uncertain) { return 'affected'; }
                $unknown |= $uncertain;
            }
            if (empty($a['versions']) && !$ranges) { $unknown = true; }
        }
        return $unknown ? 'unknown' : 'not-affected';
    }
}
