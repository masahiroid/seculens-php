<?php
declare(strict_types=1);
namespace SecuLens;

final class Runner
{
    public static function scan(array $options): array
    {
        $language = $options['lang'] ?? 'en'; $style = $options['report-style'] ?? 'standard';
        if (!in_array($language,['en','ja'],true) || !in_array($style,['standard','customer'],true)) { throw new \InvalidArgumentException('Invalid language or report style'); }
        $sbomText = Json::read($options['sbom']); $sbom = Sbom::parse(Json::decode($sbomText));
        if (empty($options['db']) === empty($options['fetch-osv'])) { throw new \InvalidArgumentException('Choose exactly one of --db and --fetch-osv'); }
        $coolOff = ($options['cool-off'] ?? null) === null ? null : Integrity::parseCoolOffDays($options['cool-off']);
        $databaseText = !empty($options['fetch-osv']) ? Json::encode(Database::fetch($sbom['components']), true)."\n" : Json::read($options['db']);
        $records = Database::validate(Json::decode($databaseText));
        $policy = !empty($options['policy']) ? Licenses::validatePolicy(Json::decode(Json::read($options['policy']))) : [];
        $waivers = !empty($options['waivers']) ? Waivers::validate(json_decode(Json::read($options['waivers']), false, 128, JSON_THROW_ON_ERROR)) : null;
        $report = Assessment::scan($sbomText,$records,[
            'policy'=>$policy,'customer'=>$options['customer'] ?? 'Customer','target'=>($options['target'] ?? null) ?: basename($options['sbom']),
            'databaseSource'=>!empty($options['fetch-osv']) ? 'OSV API candidate snapshot' : $options['db'],'databaseHash'=>hash('sha256',$databaseText),
        ]);
        if (!empty($options['source'])) {
            $analysis = Analysis::scan($options['source']);
            array_push($report['findings'], ...$analysis['findings']); $report['sourceAnalysis'] = $analysis['metadata'];
        }
        $lockfiles = !empty($options['source']) ? $options['source'] : dirname($options['sbom']);
        array_push($report['findings'], ...Integrity::checkLockfileIntegrity($lockfiles, $sbom));
        if ($coolOff !== null) { array_push($report['findings'], ...Integrity::checkPackageCoolOff($sbom['components'], $coolOff, null, $options['release-dates'] ?? null)); }
        if ($waivers !== null) {
            $report['findings'] = Waivers::apply($report['findings'], $waivers['waivers'], substr($report['createdAt'], 0, 10));
            $report['limitations'][] = Waivers::LIMITATION;
        }
        $directory = $options['output'] ?? 'reports'; Json::localPath($directory);
        if (!is_dir($directory) && !mkdir($directory,0700,true) && !is_dir($directory)) { throw new \RuntimeException('Cannot create report output directory'); }
        $temporary = $directory.'/.seculens-'.bin2hex(random_bytes(8));
        if (!mkdir($temporary,0700)) { throw new \RuntimeException('Cannot create temporary report directory'); }
        try {
            WordReport::write($report,$temporary.'/report.docx',$language,$style,$options['issuer'] ?? '');
            Json::write($temporary.'/report.json',Json::encode($report,true)."\n");
            Json::write($temporary.'/sbom.json',$sbomText); Json::write($temporary.'/database.json',$databaseText);
            foreach (['report.docx','report.json','sbom.json','database.json'] as $name) {
                chmod($temporary.'/'.$name,0600);
                if (!rename($temporary.'/'.$name,$directory.'/'.$name)) { throw new \RuntimeException("Cannot save output: $name"); }
            }
        } finally {
            foreach (glob($temporary.'/*') ?: [] as $file) { @unlink($file); }
            @rmdir($temporary);
        }
        return ['report'=>$report,'exitCode'=>Assessment::exitCode($report,(bool)($options['fail-on-findings'] ?? false))];
    }
}
