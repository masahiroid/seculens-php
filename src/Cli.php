<?php
declare(strict_types=1);
namespace SecuLens;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Formatter\OutputFormatter;

final class Cli
{
    public static function application(): Application
    {
        $app=new Application('SecuLens',Assessment::VERSION);
        $scan=new Command('scan'); $scan->setDescription('Assess SPDX/CycloneDX SBOM and write Word/JSON reports');
        $scan->addArgument('sbom',InputArgument::REQUIRED,'SBOM JSON file');
        foreach (['db'=>'Local OSV snapshot JSON','policy'=>'License policy JSON','source'=>'PHP source file/directory','customer'=>'Customer name','target'=>'Target system name','issuer'=>'Report preparer'] as $name=>$help) { $scan->addOption($name,null,InputOption::VALUE_REQUIRED,$help,$name==='customer'?'Customer':null); }
        $scan->addOption('fetch-osv',null,InputOption::VALUE_NONE,'Fetch OSV candidates; sends package names/ecosystems only');
        $scan->addOption('lang',null,InputOption::VALUE_REQUIRED,'Word language: en / ja','en');
        $scan->addOption('report-style',null,InputOption::VALUE_REQUIRED,'Report layout: standard / customer','standard');
        $scan->addOption('output',null,InputOption::VALUE_REQUIRED,'Report output directory','reports');
        $scan->addOption('fail-on-findings',null,InputOption::VALUE_NONE,'Exit 1 on vulnerabilities, denied licenses or security candidates');
        $scan->setCode(static fn(InputInterface $in,OutputInterface $out): int => self::guard($out,static fn(): int => self::runScan(['sbom'=>$in->getArgument('sbom')]+$in->getOptions(),$out)));
        $app->add($scan);
        $sbom=new Command('sbom'); $sbom->setDescription('Generate SBOM with separately installed Syft');
        $sbom->addArgument('directory',InputArgument::REQUIRED,'Project directory');
        $sbom->addOption('format',null,InputOption::VALUE_REQUIRED,'cyclonedx / spdx','cyclonedx')->addOption('output',null,InputOption::VALUE_REQUIRED,'Output file','sbom.json')->addOption('syft',null,InputOption::VALUE_REQUIRED,'Syft executable','syft');
        $sbom->setCode(static fn(InputInterface $in,OutputInterface $out): int => self::guard($out,static fn(): int => self::runGeneration(['directory'=>$in->getArgument('directory')]+$in->getOptions(),$out)));
        $app->add($sbom);
        $wizard=new Command('wizard'); $wizard->setDescription('Interactive English/Japanese setup');
        $wizard->addOption('lang',null,InputOption::VALUE_REQUIRED,'Wizard/report language: en / ja');
        $wizard->setCode(static function(InputInterface $in,OutputInterface $out): int {
            return self::guard($out,static function() use($in,$out): int {
                $w=new Wizard(STDIN,static function(string $text,bool $newline) use($out): void { $out->write(OutputFormatter::escape($text),$newline); });
                $options=$w->settings($in->getOption('lang'));
                if ($options===null) { return 0; }
                return $options['operation']==='scan'?self::runScan($options,$out):self::runGeneration($options,$out);
            });
        });
        $app->add($wizard); $app->setDefaultCommand('wizard');
        return $app;
    }
    private static function guard(OutputInterface $out,callable $operation): int
    {
        try { return $operation(); }
        catch (\Throwable $e) { $out->writeln('<error>'.OutputFormatter::escape($e->getMessage()).'</error>'); return 2; }
    }
    private static function runScan(array $options,OutputInterface $out): int
    {
        $result=Runner::scan($options);
        $out->writeln(OutputFormatter::escape(($options['lang']==='ja'?'検査完了。レポート出力先: ':'Assessment complete. Reports: ').$options['output']));
        return $result['exitCode'];
    }
    private static function runGeneration(array $options,OutputInterface $out): int
    {
        Generator::generate($options['directory'],$options['format'],$options['output'],$options['syft']);
        $out->writeln(OutputFormatter::escape('SBOM saved: '.$options['output'])); return 0;
    }
}
