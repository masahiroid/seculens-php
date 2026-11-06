<?php
declare(strict_types=1);
namespace SecuLens;

/** CVSS v4.0 scoring per FIRST's specification, using its published MacroVector tables. */
final class Cvss4
{
    private const METRICS = ['AV'=>['N','A','L','P'],'AC'=>['L','H'],'AT'=>['N','P'],'PR'=>['N','L','H'],'UI'=>['N','P','A'],'VC'=>['H','L','N'],'VI'=>['H','L','N'],'VA'=>['H','L','N'],'SC'=>['H','L','N'],'SI'=>['H','L','N'],'SA'=>['H','L','N'],'E'=>['X','A','P','U'],'CR'=>['X','H','M','L'],'IR'=>['X','H','M','L'],'AR'=>['X','H','M','L'],'MAV'=>['X','N','A','L','P'],'MAC'=>['X','L','H'],'MAT'=>['X','N','P'],'MPR'=>['X','N','L','H'],'MUI'=>['X','N','P','A'],'MVC'=>['X','H','L','N'],'MVI'=>['X','H','L','N'],'MVA'=>['X','H','L','N'],'MSC'=>['X','H','L','N'],'MSI'=>['X','S','H','L','N'],'MSA'=>['X','S','H','L','N'],'S'=>['X','N','P'],'AU'=>['X','N','Y'],'R'=>['X','A','U','I'],'V'=>['X','D','C'],'RE'=>['X','L','M','H'],'U'=>['X','Clear','Green','Amber','Red']];
    private const BASE = ['AV','AC','AT','PR','UI','VC','VI','VA','SC','SI','SA'];
    private const LEVELS = ['AV'=>['N'=>0.0,'A'=>0.1,'L'=>0.2,'P'=>0.3],'PR'=>['N'=>0.0,'L'=>0.1,'H'=>0.2],'UI'=>['N'=>0.0,'P'=>0.1,'A'=>0.2],'AC'=>['L'=>0.0,'H'=>0.1],'AT'=>['N'=>0.0,'P'=>0.1],'VC'=>['H'=>0.0,'L'=>0.1,'N'=>0.2],'VI'=>['H'=>0.0,'L'=>0.1,'N'=>0.2],'VA'=>['H'=>0.0,'L'=>0.1,'N'=>0.2],'SC'=>['H'=>0.1,'L'=>0.2,'N'=>0.3],'SI'=>['S'=>0.0,'H'=>0.1,'L'=>0.2,'N'=>0.3],'SA'=>['S'=>0.0,'H'=>0.1,'L'=>0.2,'N'=>0.3],'CR'=>['H'=>0.0,'M'=>0.1,'L'=>0.2],'IR'=>['H'=>0.0,'M'=>0.1,'L'=>0.2],'AR'=>['H'=>0.0,'M'=>0.1,'L'=>0.2]];
    private static ?array $tables = null;

    private static function parse(mixed $vector): ?array
    {
        if (!is_string($vector) || !str_starts_with($vector, 'CVSS:4.0/')) { return null; }
        $order = array_keys(self::METRICS); $metrics = []; $position = -1;
        foreach (array_slice(explode('/', $vector), 1) as $token) {
            $pair = explode(':', $token);
            if (count($pair) !== 2 || !isset(self::METRICS[$pair[0]])) { return null; }
            $index = array_search($pair[0], $order, true);
            if ($index <= $position || !in_array($pair[1], self::METRICS[$pair[0]], true)) { return null; }
            $position = $index; $metrics[$pair[0]] = $pair[1];
        }
        foreach (self::BASE as $key) { if (!isset($metrics[$key])) { return null; } }
        return $metrics;
    }
    /** Threat and requirement metrics default to worst case; modified metrics override base. */
    private static function effective(array $m, string $key): string
    {
        $selected = $m[$key] ?? 'X';
        if ($key === 'E' && $selected === 'X') { return 'A'; }
        if (in_array($key, ['CR','IR','AR'], true) && $selected === 'X') { return 'H'; }
        $modified = $m['M'.$key] ?? null;
        return $modified !== null && $modified !== 'X' ? $modified : $selected;
    }
    /** Returns the score, or null when the vector is not a valid CVSS v4.0 vector. */
    public static function score(mixed $vector): ?float
    {
        $m = self::parse($vector);
        if ($m === null) { return null; }
        $get = static fn(string $key): string => self::effective($m, $key);
        $impact = array_map($get, ['VC','VI','VA','SC','SI','SA']);
        if (array_unique($impact) === ['N']) { return 0.0; }
        self::$tables ??= json_decode(Json::read(dirname(__DIR__).'/schemas/cvss-v4-data.json'), true, 16, JSON_THROW_ON_ERROR);
        ['lookup'=>$lookup,'maxComposed'=>$composed,'maxSeverity'=>$severity] = self::$tables;
        [$av,$pr,$ui] = [$get('AV'),$get('PR'),$get('UI')];
        $eq1 = $av === 'N' && $pr === 'N' && $ui === 'N' ? 0 : (($av === 'N' || $pr === 'N' || $ui === 'N') && $av !== 'P' ? 1 : 2);
        $eq2 = $get('AC') === 'L' && $get('AT') === 'N' ? 0 : 1;
        [$vc,$vi,$va] = [$get('VC'),$get('VI'),$get('VA')];
        $eq3 = $vc === 'H' && $vi === 'H' ? 0 : ($vc === 'H' || $vi === 'H' || $va === 'H' ? 1 : 2);
        $eq4 = $get('MSI') === 'S' || $get('MSA') === 'S' ? 0 : ($get('SC') === 'H' || $get('SI') === 'H' || $get('SA') === 'H' ? 1 : 2);
        $eq5 = ['A'=>0,'P'=>1,'U'=>2][$get('E')];
        $eq6 = ($get('CR') === 'H' && $vc === 'H') || ($get('IR') === 'H' && $vi === 'H') || ($get('AR') === 'H' && $va === 'H') ? 0 : 1;
        $at = static function (int ...$parts) use ($lookup): ?float { $key = implode('', $parts); return isset($lookup[$key]) ? (float) $lookup[$key] : null; };
        $value = $at($eq1,$eq2,$eq3,$eq4,$eq5,$eq6);
        if ($eq3 === 0 && $eq6 === 0) {
            $left = $at($eq1,$eq2,$eq3,$eq4,$eq5,$eq6+1); $right = $at($eq1,$eq2,$eq3+1,$eq4,$eq5,$eq6);
            $lowerEq3Eq6 = $left !== null && $right !== null && $left > $right ? $left : $right;
        } elseif ($eq3 === 1 && $eq6 === 0) { $lowerEq3Eq6 = $at($eq1,$eq2,$eq3,$eq4,$eq5,$eq6+1); }
        elseif ($eq3 === 2) { $lowerEq3Eq6 = null; }
        else { $lowerEq3Eq6 = $at($eq1,$eq2,$eq3+1,$eq4,$eq5,$eq6); }
        $lower = [$at($eq1+1,$eq2,$eq3,$eq4,$eq5,$eq6),$at($eq1,$eq2+1,$eq3,$eq4,$eq5,$eq6),$lowerEq3Eq6,$at($eq1,$eq2,$eq3,$eq4+1,$eq5,$eq6),$at($eq1,$eq2,$eq3,$eq4,$eq5+1,$eq6)];
        $d = [];
        // The first highest-severity vector that is not below the scored vector sets the distances.
        foreach ($composed['eq1'][$eq1] as $a) { foreach ($composed['eq2'][$eq2] as $b) { foreach ($composed['eq3'][$eq3][$eq6] as $c) { foreach ($composed['eq4'][$eq4] as $e4) { foreach ($composed['eq5'][$eq5] as $e5) {
            $highest = [];
            foreach (array_filter(explode('/', $a.$b.$c.$e4.$e5)) as $token) { [$k,$v] = explode(':', $token); $highest[$k] = $v; }
            $ok = true;
            foreach (self::LEVELS as $key=>$levels) { $d[$key] = $levels[$get($key)] - $levels[$highest[$key]]; if ($d[$key] < 0) { $ok = false; } }
            if ($ok) { break 5; }
        } } } } }
        $step = 0.1;
        $current = [$d['AV']+$d['PR']+$d['UI'],$d['AC']+$d['AT'],$d['VC']+$d['VI']+$d['VA']+$d['CR']+$d['IR']+$d['AR'],$d['SC']+$d['SI']+$d['SA'],0.0];
        $depth = [$severity['eq1'][$eq1]*$step,$severity['eq2'][$eq2]*$step,$severity['eq3eq6'][$eq3][$eq6]*$step,$severity['eq4'][$eq4]*$step,1.0];
        $total = 0.0; $existing = 0;
        foreach ($lower as $i=>$score) {
            if ($score === null) { continue; }
            $existing++; $total += ($value - $score) * ($current[$i] / $depth[$i]);
        }
        $result = min(max($value - ($existing ? $total / $existing : 0.0), 0.0), 10.0);
        return floor($result * 10 + 0.5) / 10;
    }
}
