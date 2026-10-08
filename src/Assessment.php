<?php
declare(strict_types=1);
namespace SecuLens;

final class Assessment
{
    public const VERSION = '0.1.2';
    public const LIMITATIONS = [
        'No match means no matching record in the supplied database snapshot, not absence of vulnerabilities.',
        'License policy checks are not a legal compliance determination.',
        'AST rules identify review candidates and complexity, not proven exploitability.',
        'SBOM content and package identifiers are supplied by the generating tool.',
        'Packagist matching supports stable numeric versions and SemVer prereleases only; Composer branches and other version forms may be unassessed.',
    ];
    public static function scan(string $sbomText, array $records, array $options = []): array
    {
        $sbom = Sbom::parse(Json::decode($sbomText)); Database::validate($records);
        $policy = Licenses::validatePolicy($options['policy'] ?? []);
        $report = [
            'schemaVersion'=>'1.1','tool'=>['name'=>'SecuLens','version'=>self::VERSION],
            'createdAt'=>$options['createdAt'] ?? (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d\TH:i:s.v\Z'),
            'customer'=>$options['customer'] ?? 'Customer','target'=>$options['target'] ?? 'SBOM',
            'sbomSha256'=>hash('sha256', $sbomText),
            'database'=>['source'=>$options['databaseSource'] ?? 'OSV snapshot','sha256'=>$options['databaseHash'] ?? hash('sha256', Json::encode($records))],
            'sbom'=>$sbom,'checks'=>[],'findings'=>[],'limitations'=>self::LIMITATIONS,
        ];
        foreach ($sbom['components'] as $c) {
            array_push($report['findings'], ...Licenses::findings($c, $policy));
            if (!Matcher::supported($c)) {
                $reason = !isset($c['ecosystem']) ? 'Supported package URL required (npm, pypi or composer)' : (!isset($c['version']) ? 'Package version is missing' : 'Unsupported package version syntax');
                $report['checks'][] = ['componentId'=>$c['id'],'status'=>'unassessed','recordsChecked'=>0,'reason'=>$reason];
                $report['findings'][] = ['category'=>'coverage','ruleId'=>'PACKAGE-IDENTITY','subject'=>$c['id'],'status'=>'unassessed','summary'=>'Component could not be assessed','evidence'=>$reason,'recommendation'=>'Regenerate the SBOM with complete package URLs and versions.'];
                continue;
            }
            $candidates = array_filter($records, static fn(array $r): bool => (bool) array_filter($r['affected'], static fn(array $a): bool => Matcher::samePackage($c, $a['package'])));
            $matched = false; $uncertain = false;
            foreach ($candidates as $r) {
                $result = Matcher::match($c, $r);
                if ($result === 'not-affected') { continue; }
                if ($result === 'unknown') {
                    $uncertain = true;
                    $report['findings'][] = ['category'=>'coverage','ruleId'=>$r['id'],'subject'=>$c['id'],'status'=>'unassessed','summary'=>'Advisory could not be fully evaluated','evidence'=>"{$c['name']}@{$c['version']}; unsupported or incomplete version range",'recommendation'=>'Review the advisory and package version manually.'];
                    continue;
                }
                $matched = true;
                $report['findings'][] = ['category'=>'vulnerability','ruleId'=>$r['id'],'subject'=>$c['id'],'status'=>'affected','summary'=>$r['summary'] ?? $r['id'],'evidence'=>"{$c['ecosystem']}:{$c['name']}@{$c['version']}; matched against affected versions/ranges in {$r['id']}",'recommendation'=>'Review the advisory references for a fixed version and validate the upgrade.','severity'=>Severity::record($r, $c),'aliases'=>$r['aliases'] ?? [],'references'=>array_column($r['references'] ?? [], 'url')];
            }
            $check = ['componentId'=>$c['id'],'status'=>$uncertain ? 'unassessed' : ($matched ? 'matched' : 'no-match'),'recordsChecked'=>count($candidates)];
            if ($uncertain) { $check['reason'] = 'One or more candidate records require manual review'; }
            $report['checks'][] = $check;
        }
        $report['findings'] = self::consolidate($report['findings']);
        return $report;
    }
    private static function consolidate(array $findings): array
    {
        $groups = [];
        foreach ($findings as $f) {
            if ($f['category'] !== 'vulnerability') { $groups[] = $f; continue; }
            do {
                $changed = false;
                foreach ($groups as $i => $g) {
                    if ($g['category'] !== 'vulnerability' || $g['subject'] !== $f['subject']) { continue; }
                    $ids = [$f['ruleId'], ...$f['aliases']]; $other = [$g['ruleId'], ...$g['aliases']];
                    if (!array_intersect($ids, $other)) { continue; }
                    $all = array_unique([...$ids, ...$other]); sort($all, SORT_STRING);
                    $f['ruleId'] = array_shift($all); $f['aliases'] = array_values($all);
                    $f['severity'] = Severity::merge($f['severity'], $g['severity']);
                    $f['references'] = array_values(array_unique([...$f['references'], ...$g['references']])); sort($f['references'], SORT_STRING);
                    $evidence = [$f['evidence'], $g['evidence']]; sort($evidence, SORT_STRING); $f['evidence'] = implode(' | ', $evidence);
                    unset($groups[$i]); $changed = true;
                }
            } while ($changed);
            $groups[] = $f;
        }
        $groups = array_values($groups);
        usort($groups, static fn(array $a, array $b): int => [$a['category'],$a['subject'],$a['ruleId']] <=> [$b['category'],$b['subject'],$b['ruleId']]);
        return $groups;
    }
    public static function exitCode(array $report, bool $fail): int
    {
        if ($fail && array_filter($report['findings'], static fn(array $f): bool => in_array($f['category'], ['vulnerability','security'], true) || $f['status'] === 'denied')) { return 1; }
        return array_filter($report['checks'], static fn(array $c): bool => $c['status'] === 'unassessed') || array_filter($report['findings'], static fn(array $f): bool => $f['category'] === 'coverage') ? 2 : 0;
    }
}
