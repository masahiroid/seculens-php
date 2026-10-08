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
        $databaseText = !empty($options['fetch-osv']) ? Json::encode(Database::fetch($sbom['components']), true)."\n" : Json::read($options['db']);
        $records = Database::validate(Json::decode($databaseText));
        $policy = !empty($options['policy']) ? Licenses::validatePolicy(Json::decode(Json::read($options['policy']))) : [];
        $report = Assessment::scan($sbomText,$records,[
            'policy'=>$policy,'customer'=>$options['customer'] ?? 'Customer','target'=>($options['target'] ?? null) ?: basename($options['sbom']),
            'databaseSource'=>!empty($options['fetch-osv']) ? 'OSV API candidate snapshot' : $options['db'],'databaseHash'=>hash('sha256',$databaseText),
        ]);
        if (!empty($options['source'])) {
            $analysis = Analysis::scan($options['source']);
            array_push($report['findings'], ...$analysis['findings']); $report['sourceAnalysis'] = $analysis['metadata'];
        }
        $directory = $options['output'] ?? 'reports';
        if (!is_dir($directory) && !mkdir($directory,0777,true) && !is_dir($directory)) { throw new \RuntimeException('Cannot create report output directory'); }
        $temporary = $directory.'/.seculens-'.bin2hex(random_bytes(8));
        if (!mkdir($temporary,0700)) { throw new \RuntimeException('Cannot create temporary report directory'); }
        try {
            WordReport::write($report,$temporary.'/report.docx',$language,$style,$options['issuer'] ?? '');
            Json::write($temporary.'/report.json',Json::encode($report,true)."\n");
            Json::write($temporary.'/sbom.json',$sbomText); Json::write($temporary.'/database.json',$databaseText);
            foreach (['report.docx','report.json','sbom.json','database.json'] as $name) {
                if (!rename($temporary.'/'.$name,$directory.'/'.$name)) { throw new \RuntimeException("Cannot save output: $name"); }
            }
        } finally {
            foreach (glob($temporary.'/*') ?: [] as $file) { @unlink($file); }
            @rmdir($temporary);
        }
        return ['report'=>$report,'exitCode'=>Assessment::exitCode($report,(bool)($options['fail-on-findings'] ?? false))];
    }
}
