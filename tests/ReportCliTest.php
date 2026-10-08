<?php
declare(strict_types=1);
namespace SecuLens\Tests;
use PHPUnit\Framework\TestCase;
use SecuLens\{Assessment,Database,Json,Runner,WordReport};
use Symfony\Component\Process\Process;

final class ReportCliTest extends TestCase
{
    private string $directory;
    protected function setUp(): void { $this->directory=sys_get_temp_dir().'/seculens-report-'.bin2hex(random_bytes(6));mkdir($this->directory); }
    protected function tearDown(): void
    {
        $items=new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->directory,\FilesystemIterator::SKIP_DOTS),\RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($items as $file) { $file->isDir()?rmdir($file->getPathname()):unlink($file->getPathname()); }rmdir($this->directory);
    }
    private function options(): array
    {
        $base=dirname(__DIR__).'/examples/';
        return ['sbom'=>$base.'cyclonedx.json','db'=>$base.'database.json','policy'=>$base.'policy.json','source'=>$base,'lang'=>'ja','report-style'=>'customer','output'=>$this->directory,'customer'=>'顧客 & Example <Company>','target'=>'PHP target','issuer'=>'Assessment team'];
    }
    public function testCustomerReportFontAndJsonEvidence(): void
    {
        $options=$this->options();$result=Runner::scan($options);
        self::assertSame(0,$result['exitCode']);
        foreach(['report.docx','report.json','sbom.json','database.json'] as $name) { self::assertFileExists($this->directory.'/'.$name); }
        self::assertSame(hash_file('sha256',$options['sbom']),$result['report']['sbomSha256']);
        self::assertSame(hash_file('sha256',$options['db']),$result['report']['database']['sha256']);
        self::assertSame('PHP',$result['report']['sourceAnalysis']['language']);
        $zip=new \ZipArchive();self::assertTrue($zip->open($this->directory.'/report.docx'));
        $document=$zip->getFromName('word/document.xml');$xml=new \DOMDocument();self::assertTrue($xml->loadXML($document,LIBXML_NONET));
        self::assertStringContainsString('ソフトウェアセキュリティ評価報告書',$document);self::assertStringContainsString('顧客 &amp; Example &lt;Company&gt;',$document);self::assertStringContainsString('F-001',$document);self::assertStringContainsString('tblHeader',$document);self::assertStringContainsString('FEE2E2',$document);
        $table=new \DOMDocument();$table->loadXML($zip->getFromName('word/fontTable.xml'));
        $xp=new \DOMXPath($table);$xp->registerNamespace('w','http://schemas.openxmlformats.org/wordprocessingml/2006/main');
        $entry=$xp->query('//w:embedRegular')->item(0);self::assertNotNull($entry);
        $guid=$entry->getAttributeNS('http://schemas.openxmlformats.org/wordprocessingml/2006/main','fontKey');
        $key=strrev(hex2bin(str_replace(['{','}','-'],'',$guid)));$font=$zip->getFromName('word/fonts/NotoSansJP.odttf');
        for($i=0;$i<32;$i++){$font[$i]=chr(ord($font[$i])^ord($key[$i%16]));}
        self::assertSame(hash_file('sha256',dirname(__DIR__).'/assets/NotoSansJP-Regular.otf'),hash('sha256',$font));$zip->close();
    }
    public function testEnglishStandardReportAndSourceOmitted(): void
    {
        $o=$this->options();$o['lang']='en';$o['report-style']='standard';$o['source']=null;
        $result=Runner::scan($o);self::assertArrayNotHasKey('sourceAnalysis',$result['report']);
        $zip=new \ZipArchive();$zip->open($this->directory.'/report.docx');
        self::assertStringContainsString('Software Security Assessment Report',$zip->getFromName('word/document.xml'));self::assertFalse($zip->getFromName('word/fonts/NotoSansJP.odttf'));$zip->close();
    }
    public function testSyntaxCoverageAndExitCodePrecedence(): void
    {
        file_put_contents($this->directory.'/broken.php','<?php function {');$o=$this->options();$o['source']=$this->directory.'/broken.php';
        self::assertSame(2,Runner::scan($o)['exitCode']);$o['fail-on-findings']=true;self::assertSame(1,Runner::scan($o)['exitCode']);
    }
    public function testConflictingDatabaseModesDoNotCreateOutputs(): void
    {
        $o=$this->options();$o['fetch-osv']=true;
        try { Runner::scan($o);self::fail('Conflicting modes must fail'); } catch(\InvalidArgumentException $e) { self::assertStringContainsString('exactly one',$e->getMessage()); }
        self::assertFileDoesNotExist($this->directory.'/report.docx');
    }
    public function testInvalidCliOptionsAndEofAreSafe(): void
    {
        $command=dirname(__DIR__).'/bin/seculens';
        $p=new Process([PHP_BINARY,$command,'scan','missing.json','--unknown']);$p->run();self::assertSame(2,$p->getExitCode());
        $p=new Process([PHP_BINARY,$command,'wizard','--lang','ja']);$p->setInput('');$p->run();self::assertSame(0,$p->getExitCode());self::assertStringContainsString('中止しました',$p->getOutput());
    }
    public function testGeneratorArgumentsArePassedWithoutShellEvaluation(): void
    {
        $fake=$this->directory.'/fake-syft';
        $fixture=Json::read(dirname(__DIR__).'/examples/cyclonedx.json');
        file_put_contents($fake,"#!".PHP_BINARY."\n<?php\nfile_put_contents(__DIR__.'/args.json',json_encode(\$argv));\necho ".var_export($fixture,true).";\n");chmod($fake,0755);
        $target=$this->directory.'/project $(touch executed)';mkdir($target);
        \SecuLens\Generator::generate($target,'cyclonedx',$this->directory.'/bom.json',$fake);
        $args=Json::decode(Json::read($this->directory.'/args.json'));self::assertSame('dir:'.realpath($target),$args[1]);self::assertSame(['-o','cyclonedx-json'],array_slice($args,2));self::assertFileDoesNotExist($this->directory.'/executed');self::assertSame('CycloneDX',\SecuLens\Sbom::parse(Json::decode(Json::read($this->directory.'/bom.json')))['format']);
    }
}
