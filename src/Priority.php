<?php
declare(strict_types=1);
namespace SecuLens;

/** Customer-context prioritization. Severity is never changed; every adjustment records its assertion. */
final class Priority
{
    private const EFFECTS = ['exposure'=>['internet'=>1,'internal'=>0,'isolated'=>-1],'reachability'=>['reachable'=>1,'unknown'=>0,'not-reachable'=>-1],'criticality'=>['high'=>1,'medium'=>0,'low'=>-1]];
    // Unrated advisories rank with High until reviewed, so missing metadata never lowers urgency.
    private const BASELINE = ['critical'=>1,'high'=>2,'medium'=>3,'low'=>4,'none'=>4,'unknown'=>2];

    private static function text(mixed $value): bool { return is_string($value) && trim($value) !== ''; }
    private static function validateEntry(mixed $entry, string $path, array $identity): void
    {
        if (!is_array($entry) || array_is_list($entry)) { throw new \InvalidArgumentException("Policy $path must be an object"); }
        foreach (array_keys($entry) as $key) {
            if (!isset(self::EFFECTS[$key]) && $key !== 'justification' && !in_array($key, $identity, true)) { throw new \InvalidArgumentException("Policy $path has unknown key $key"); }
        }
        $stated = array_filter(array_keys(self::EFFECTS), static fn(string $factor): bool => array_key_exists($factor, $entry));
        if (!$stated) { throw new \InvalidArgumentException("Policy $path must state at least one factor"); }
        foreach ($stated as $factor) {
            if (!is_string($entry[$factor]) || !isset(self::EFFECTS[$factor][$entry[$factor]])) { throw new \InvalidArgumentException("Policy $path.$factor has an unsupported value"); }
        }
        if (!self::text($entry['justification'] ?? null)) { throw new \InvalidArgumentException("Policy $path.justification is required"); }
    }
    public static function validateContext(mixed $context): array
    {
        if (!is_array($context) || ($context !== [] && array_is_list($context))) { throw new \InvalidArgumentException('Policy context must be an object'); }
        foreach (array_keys($context) as $key) {
            if (!in_array($key, ['defaults','components'], true)) { throw new \InvalidArgumentException("Policy context has unknown key $key"); }
        }
        if (array_key_exists('defaults', $context)) { self::validateEntry($context['defaults'], 'context.defaults', []); }
        if (array_key_exists('components', $context)) {
            if (!is_array($context['components']) || !array_is_list($context['components'])) { throw new \InvalidArgumentException('Policy context.components must be an array'); }
            foreach ($context['components'] as $i => $entry) {
                $path = "context.components[$i]";
                self::validateEntry($entry, $path, ['name','ecosystem']);
                if (!self::text($entry['name'] ?? null)) { throw new \InvalidArgumentException("Policy $path.name is required"); }
                if (array_key_exists('ecosystem', $entry) && !in_array($entry['ecosystem'], ['npm','PyPI','Packagist'], true)) { throw new \InvalidArgumentException("Policy $path.ecosystem is not supported"); }
            }
        }
        return $context;
    }
    public static function component(string $level, ?array $component, array $context): array
    {
        $factors = [];
        foreach (self::EFFECTS as $factor => $effects) {
            $source = 'context.defaults'; $entry = $context['defaults'] ?? null;
            foreach ($context['components'] ?? [] as $i => $candidate) {
                if (isset($candidate[$factor]) && $candidate['name'] === ($component['name'] ?? null) && (!isset($candidate['ecosystem']) || $candidate['ecosystem'] === ($component['ecosystem'] ?? null))) {
                    $source = "context.components[$i]"; $entry = $candidate; break;
                }
            }
            if ($entry !== null && isset($entry[$factor])) {
                $factors[] = ['factor'=>$factor,'value'=>$entry[$factor],'effect'=>$effects[$entry[$factor]],'source'=>$source,'justification'=>$entry['justification']];
            }
        }
        $baseline = self::BASELINE[$level];
        // A score of None has no impact to weigh, so context cannot raise it.
        $rank = $level === 'none' ? $baseline : min(max($baseline - array_sum(array_column($factors, 'effect')), 1), 4);
        return ['level'=>"P$rank",'baseline'=>"P$baseline",'factors'=>$factors];
    }
    public static function apply(array $findings, array $components, array $context): array
    {
        foreach ($findings as $i => $f) {
            if ($f['category'] !== 'vulnerability') { continue; }
            $component = null;
            foreach ($components as $c) { if ($c['id'] === $f['subject']) { $component = $c; break; } }
            $findings[$i]['priority'] = self::component($f['severity']['level'] ?? 'unknown', $component, $context);
        }
        return $findings;
    }
}
