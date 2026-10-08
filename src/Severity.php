<?php
declare(strict_types=1);
namespace SecuLens;

final class Severity
{
    public const LEVELS = ['critical','high','medium','low','none','unknown'];
    public static function cvss3(mixed $vector): ?float
    {
        if (!is_string($vector) || !preg_match('~^CVSS:3\.[01]/~', $vector)) { return null; }
        $allowed = ['AV'=>'NALP','AC'=>'LH','PR'=>'NLH','UI'=>'NR','S'=>'UC','C'=>'NLH','I'=>'NLH','A'=>'NLH','E'=>'XUPFH','RL'=>'XOTWU','RC'=>'XURC','CR'=>'XLMH','IR'=>'XLMH','AR'=>'XLMH','MAV'=>'XNALP','MAC'=>'XLH','MPR'=>'XNLH','MUI'=>'XNR','MS'=>'XUC','MC'=>'XNLH','MI'=>'XNLH','MA'=>'XNLH'];
        $m = [];
        foreach (array_slice(explode('/', $vector), 1) as $token) {
            $parts = explode(':', $token);
            if (count($parts) !== 2) { return null; }
            [$key, $value] = $parts;
            if (isset($m[$key]) || !isset($allowed[$key]) || strlen($value) !== 1 || !str_contains($allowed[$key], $value)) { return null; }
            $m[$key] = $value;
        }
        foreach (['AV','AC','PR','UI','S','C','I','A'] as $key) { if (!isset($m[$key])) { return null; } }
        $weights = ['N'=>0.0,'L'=>0.22,'H'=>0.56];
        $iss = 1 - (1 - $weights[$m['C']]) * (1 - $weights[$m['I']]) * (1 - $weights[$m['A']]);
        $changed = $m['S'] === 'C';
        $impact = $changed ? 7.52 * ($iss - 0.029) - 3.25 * ($iss - 0.02) ** 15 : 6.42 * $iss;
        if ($impact <= 0) { return 0.0; }
        $av = ['N'=>0.85,'A'=>0.62,'L'=>0.55,'P'=>0.2][$m['AV']];
        $ac = ['L'=>0.77,'H'=>0.44][$m['AC']];
        $pr = ['N'=>0.85,'L'=>$changed ? 0.68 : 0.62,'H'=>$changed ? 0.5 : 0.27][$m['PR']];
        $ui = ['N'=>0.85,'R'=>0.62][$m['UI']];
        $score = min(($impact + 8.22 * $av * $ac * $pr * $ui) * ($changed ? 1.08 : 1), 10);
        $integer = (int) floor($score * 100000 + 0.5);
        return $integer % 10000 === 0 ? $integer / 100000 : (floor($integer / 10000) + 1) / 10;
    }
    public static function level(float $score): string
    {
        return $score >= 9 ? 'critical' : ($score >= 7 ? 'high' : ($score >= 4 ? 'medium' : ($score > 0 ? 'low' : 'none')));
    }
    public static function merge(array ...$values): array
    {
        $sources = [];
        foreach ($values as $v) { foreach ($v['sources'] ?? [] as $s) { $sources[Json::encode($s)] = $s; } }
        $sources = array_values($sources);
        usort($sources, static fn(array $a, array $b): int => [$a['recordId'],$a['field'],$a['value']] <=> [$b['recordId'],$b['field'],$b['value']]);
        $level = 'unknown';
        foreach ($sources as $s) { if (array_search($s['level'], self::LEVELS, true) < array_search($level, self::LEVELS, true)) { $level = $s['level']; } }
        $out = ['level'=>$level,'sources'=>$sources]; $scores = [];
        foreach ($sources as $s) { if ($s['level'] === $level && isset($s['score'])) { $scores[] = $s['score']; } }
        if ($scores) { $out['score'] = max($scores); }
        return $out;
    }
    public static function record(array $record, array $c): array
    {
        $sources = []; $applicable = [];
        foreach ($record['affected'] as $i => $a) {
            if (Matcher::samePackage($c, $a['package']) && Matcher::match($c, array_replace($record, ['affected'=>[$a]])) === 'affected') { $applicable[$i] = $a; }
        }
        foreach ($applicable ?: [null] as $i => $a) {
            $override = $a !== null && is_array($a['severity'] ?? null) && $a['severity'] !== [];
            $entries = $override ? $a['severity'] : ($record['severity'] ?? []); $field = $override ? "affected[$i].severity" : 'severity';
            if (!is_array($entries)) { continue; }
            foreach ($entries as $j => $e) {
                if (!is_array($e) || !is_string($e['score'] ?? null)) { continue; }
                $score = ($e['type'] ?? '') === 'CVSS_V3' ? self::cvss3($e['score']) : null;
                $source = ['recordId'=>$record['id'],'field'=>$field.'['.$j.']','type'=>(string) ($e['type'] ?? 'unknown'),'value'=>$e['score'],'level'=>$score !== null ? self::level($score) : 'unknown'];
                if ($score !== null) { $source['score'] = $score; }
                $sources[] = $source;
            }
        }
        $labels = ['database_specific.severity'=>$record['database_specific'] ?? []];
        foreach ($applicable as $i => $a) { $labels["affected[$i].database_specific.severity"] = $a['database_specific'] ?? []; }
        foreach ($labels as $field => $data) {
            $v = is_array($data) ? ($data['severity'] ?? null) : null;
            if (!is_string($v)) { continue; }
            $sources[] = ['recordId'=>$record['id'],'field'=>$field,'type'=>'database_label','value'=>$v,'level'=>['CRITICAL'=>'critical','HIGH'=>'high','MEDIUM'=>'medium','MODERATE'=>'medium','LOW'=>'low','NONE'=>'none'][strtoupper($v)] ?? 'unknown'];
        }
        return self::merge(['sources'=>$sources]);
    }
}
