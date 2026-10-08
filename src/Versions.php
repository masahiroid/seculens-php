<?php
declare(strict_types=1);
namespace SecuLens;

/** Ecosystem precedence, never PHP's generic version_compare for SemVer/PEP 440. */
final class Versions
{
    public static function compare(string $a, string $b, string $ecosystem): ?int
    {
        try {
            if ($ecosystem === 'PyPI') { return self::pepCompare(self::pep($a), self::pep($b)); }
            if (!in_array($ecosystem, ['npm', 'Packagist'], true)) { return null; }
            $x = self::semver($a, $ecosystem); $y = self::semver($b, $ecosystem);
            $n = self::numbers($x[0], $y[0]);
            if ($n !== 0) { return $n; }
            if ($x[1] === $y[1]) { return 0; }
            if ($x[1] === null) { return 1; }
            if ($y[1] === null) { return -1; }
            $p = explode('.', $x[1]); $q = explode('.', $y[1]);
            for ($i = 0; $i < min(count($p), count($q)); $i++) {
                if ($p[$i] === $q[$i]) { continue; }
                $pn = ctype_digit($p[$i]); $qn = ctype_digit($q[$i]);
                return $pn && $qn ? self::integer($p[$i], $q[$i]) : ($pn !== $qn ? ($pn ? -1 : 1) : (strcmp($p[$i], $q[$i]) <=> 0));
            }
            return count($p) <=> count($q);
        } catch (\InvalidArgumentException) { return null; }
    }
    private static function semver(string $v, string $ecosystem): array
    {
        $v = trim($v);
        $v = $ecosystem === 'npm' ? ltrim($v, 'v=') : (str_starts_with($v, 'v') ? substr($v, 1) : $v);
        if ($ecosystem === 'Packagist' && preg_match('/^\d+\.\d+\.\d+\.0$/', $v)) { $v = substr($v, 0, -2); }
        if (!preg_match('/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/D', $v, $m)) { throw new \InvalidArgumentException('Invalid SemVer'); }
        if (isset($m[4])) {
            foreach (explode('.', $m[4]) as $part) { if (ctype_digit($part) && strlen($part) > 1 && $part[0] === '0') { throw new \InvalidArgumentException('Leading zero in prerelease'); } }
        }
        return [[ $m[1], $m[2], $m[3] ], $m[4] ?? null];
    }
    private static function integer(string $a, string $b): int
    {
        $a = ltrim($a, '0') ?: '0'; $b = ltrim($b, '0') ?: '0';
        return strlen($a) <=> strlen($b) ?: (strcmp($a, $b) <=> 0);
    }
    private static function numbers(array $a, array $b): int
    {
        for ($i = 0; $i < max(count($a), count($b)); $i++) { $c = self::integer((string) ($a[$i] ?? '0'), (string) ($b[$i] ?? '0')); if ($c !== 0) { return $c; } }
        return 0;
    }
    /** PEP 440 ordering: epoch, release, pre, post, dev, local. */
    private static function pep(string $v): array
    {
        $re = '~^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d+)?)?(?:(?:-(\d+))|(?:[-_.]?(post|rev|r)[-_.]?(\d+)?))?(?:[-_.]?(dev)[-_.]?(\d+)?)?(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$~iD';
        if (!preg_match($re, trim($v), $m, PREG_UNMATCHED_AS_NULL)) { throw new \InvalidArgumentException('Invalid PEP 440'); }
        $tag = strtolower($m[3] ?? '');
        $pre = $tag !== '' ? [['a'=>0,'alpha'=>0,'b'=>1,'beta'=>1,'c'=>2,'rc'=>2,'pre'=>2,'preview'=>2][$tag], $m[4] ?? '0'] : null;
        $post = $m[5] ?? (isset($m[6]) ? ($m[7] ?? '0') : null);
        return ['epoch'=>$m[1] ?? '0', 'release'=>explode('.', $m[2]), 'pre'=>$pre, 'post'=>$post, 'dev'=>isset($m[8]) ? ($m[9] ?? '0') : null, 'local'=>isset($m[10]) ? preg_split('/[-_.]/', strtolower($m[10])) : null];
    }
    private static function pepCompare(array $a, array $b): int
    {
        $n = self::integer($a['epoch'], $b['epoch']) ?: self::numbers($a['release'], $b['release']);
        if ($n !== 0) { return $n; }
        $rank = static fn(array $v): int => $v['pre'] !== null ? 0 : ($v['post'] === null && $v['dev'] !== null ? -1 : 1);
        $n = $rank($a) <=> $rank($b);
        if ($n === 0 && $a['pre'] !== null && $b['pre'] !== null) { $n = $a['pre'][0] <=> $b['pre'][0] ?: self::integer($a['pre'][1], $b['pre'][1]); }
        if ($n !== 0) { return $n; }
        foreach (['post', 'dev'] as $key) {
            $x = $a[$key]; $y = $b[$key];
            if ($x === $y) { continue; }
            if ($x === null || $y === null) { return ($x === null ? -1 : 1) * ($key === 'dev' ? -1 : 1); }
            if (($n = self::integer($x, $y)) !== 0) { return $n; }
        }
        $x = $a['local']; $y = $b['local'];
        if ($x === $y) { return 0; }
        if ($x === null || $y === null) { return $x === null ? -1 : 1; }
        for ($i = 0; $i < min(count($x), count($y)); $i++) {
            if ($x[$i] === $y[$i]) { continue; }
            $xn = ctype_digit($x[$i]); $yn = ctype_digit($y[$i]);
            $n = $xn && $yn ? self::integer($x[$i], $y[$i]) : ($xn !== $yn ? ($xn ? 1 : -1) : (strcmp($x[$i], $y[$i]) <=> 0));
            if ($n !== 0) { return $n; }
        }
        return count($x) <=> count($y);
    }
}
