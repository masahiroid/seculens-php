<?php
declare(strict_types=1);
namespace SecuLens\Tests;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SecuLens\{Assessment,Database,Json,Licenses,Matcher,Severity,Sbom,Versions};

final class AssessmentTest extends TestCase
{
    public static function versions(): array
    {
        return [
            ['1.2.3','1.2.4','npm',-1],['1.2.3+foo','1.2.3+bar','npm',0],['v1.2.3','=1.2.3','npm',0],
            ['1.0.0-alpha.2','1.0.0-alpha.10','npm',-1],['1.0.0-1','1.0.0-a','npm',-1],['1.0.0-rc.1','1.0.0','npm',-1],
            ['01.2.3','1.2.3','npm',null],['1.0.0-01','1.0.0','npm',null],['1.2','1.2.0','npm',null],
            ['v5.4.0','5.4.0.0','Packagist',0],['5.4.0.1','5.4.0','Packagist',null],['dev-main','1.0.0','Packagist',null],
            ['1.0','1.0.0','PyPI',0],['1!1.0','2.0','PyPI',1],['1.0.dev1','1.0a1','PyPI',-1],
            ['1.0rc1','1.0','PyPI',-1],['1.0.post1','1.0','PyPI',1],['1.0-1','1.0.post1','PyPI',0],
            ['1.0a1.dev2','1.0a1','PyPI',-1],['1.0.post1.dev1','1.0.post1','PyPI',-1],
            ['1.0+abc.1','1.0+abc.a','PyPI',1],['1.0+foo','1.0','PyPI',1],['1.0preview1','1.0rc1','PyPI',0],
            ['invalid','1.0','PyPI',null],['1.0.0','1.0.0','Other',null],
        ];
    }
    #[DataProvider('versions')]
    public function testEcosystemPrecedence(string $a,string $b,string $eco,?int $expected): void
    {
        self::assertSame($expected,Versions::compare($a,$b,$eco));
        self::assertSame($expected===null?null:-$expected,Versions::compare($b,$a,$eco));
    }
    private function component(string $version='1.5.0'): array { return ['id'=>'test','name'=>'vendor/pkg','ecosystem'=>'Packagist','version'=>$version,'licenses'=>['MIT']]; }
    private function record(array $events): array { return ['id'=>'TEST','affected'=>[['package'=>['name'=>'vendor/pkg','ecosystem'=>'Packagist'],'ranges'=>[['type'=>'ECOSYSTEM','events'=>$events]]]]]; }
    public function testVersionBoundariesAndRepeatedIntervals(): void
    {
        $r=$this->record([['introduced'=>'1.0.0'],['fixed'=>'2.0.0'],['introduced'=>'3.0.0'],['last_affected'=>'4.0.0']]);
        foreach (['0.9.0'=>'not-affected','1.0.0'=>'affected','2.0.0'=>'not-affected','2.9.0'=>'not-affected','3.0.0'=>'affected','4.0.0'=>'affected','4.0.1'=>'not-affected'] as $v=>$state) { self::assertSame($state,Matcher::match($this->component($v),$r)); }
        self::assertSame('not-affected',Matcher::match($this->component('2.0.0'),$this->record([['introduced'=>'0'],['limit'=>'2.0.0']])));
    }
    public function testUnsupportedAndMalformedRangesAreNotClean(): void
    {
        foreach ([[['fixed'=>'2.0.0']],[['introduced'=>'0'],['fixed'=>'2.0.0'],['introduced'=>'1.0.0']],[['introduced'=>'dev-main']],[['introduced'=>'0'],['fixed'=>'bad']],[]] as $events) { self::assertSame('unknown',Matcher::match($this->component(),$this->record($events))); }
        $r=$this->record([['introduced'=>'0']]);$r['affected'][0]['ranges'][0]['type']='GIT';
        self::assertSame('unknown',Matcher::match($this->component(),$r));
        $r['withdrawn']='2026-01-01'; self::assertSame('not-affected',Matcher::match($this->component(),$r));
    }
    public function testPyPiNamesNormalizeAndExplicitVersionsMatch(): void
    {
        $c=['name'=>'Example_pkg','ecosystem'=>'PyPI','version'=>'1.0.0'];
        $r=['id'=>'PY','affected'=>[['package'=>['name'=>'example-pkg','ecosystem'=>'PyPI'],'versions'=>['1.0']]]];
        self::assertTrue(Matcher::samePackage($c,$r['affected'][0]['package']));self::assertSame('affected',Matcher::match($c,$r));
    }
    public function testSpdxAndCycloneDxIdentifySameComponents(): void
    {
        $base=dirname(__DIR__).'/examples/';
        $a=Sbom::parse(Json::decode(Json::read($base.'cyclonedx.json')));$b=Sbom::parse(Json::decode(Json::read($base.'spdx.json')));
        self::assertSame(['npm','PyPI','Packagist'],array_column($a['components'],'ecosystem'));
        self::assertSame(array_column($a['components'],'name'),array_column($b['components'],'name'));
        self::assertSame('npm',Sbom::identity('pkg:npm/%40scope/pkg@1.0.0')['ecosystem']);
        self::assertSame([],Sbom::identity('pkg:npm/%ZZ@1.0.0'));
    }
    public function testDuplicateComponentIdsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Sbom::parse(['bomFormat'=>'CycloneDX','specVersion'=>'1.6','components'=>[['name'=>'a','bom-ref'=>'same'],['name'=>'b','bom-ref'=>'same']]]);
    }
    public static function expressions(): array
    {
        return [['MIT','allowed'],['MIT OR GPL-3.0-only','allowed'],['MIT AND GPL-3.0-only','denied'],['(MIT OR GPL-3.0-only) AND Apache-2.0','allowed'],['LicenseRef-Custom','review'],['MIT OR','review'],['MIT AND (Apache-2.0','review'],['GPL-2.0-only WITH Classpath-exception-2.0','review'],['NOASSERTION','review'],['NONE','review']];
    }
    #[DataProvider('expressions')]
    public function testLicenseExpressions(string $expression,string $expected): void
    {
        self::assertSame($expected,Licenses::evaluate($expression,['allow'=>['MIT','Apache-2.0'],'deny'=>['GPL-3.0-only']]));
    }
    public function testWithRequiresFullExpressionPolicy(): void
    {
        self::assertSame('allowed',Licenses::evaluate('GPL-2.0-only WITH Classpath-exception-2.0',['allow'=>['GPL-2.0-only WITH Classpath-exception-2.0']]));
        self::assertSame('denied',Licenses::evaluate('MIT',['allow'=>['MIT'],'deny'=>['MIT']]));
    }
    public function testCvssVectorsAndUnknownSeverity(): void
    {
        self::assertSame(9.8,Severity::cvss3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'));
        self::assertSame(10.0,Severity::cvss3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'));
        self::assertSame(0.0,Severity::cvss3('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'));
        self::assertNull(Severity::cvss3('CVSS:4.0/AV:N'));
        self::assertNull(Severity::cvss3('CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'));
    }
    public function testAffectedSeverityOverridesGlobalAndAliasesConsolidate(): void
    {
        $r=$this->record([['introduced'=>'0']]);$r['aliases']=['CVE-DEMO'];$r['severity']=[['type'=>'CVSS_V3','score'=>'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H']];
        $r['affected'][0]['severity']=[['type'=>'CVSS_V3','score'=>'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N']];
        self::assertSame('medium',Severity::record($r,$this->component())['level']);
        $other=$r;$other['id']='OTHER';$other['database_specific']=['severity'=>'HIGH'];
        $sbom=Json::encode(['bomFormat'=>'CycloneDX','specVersion'=>'1.6','components'=>[['name'=>'pkg','purl'=>'pkg:composer/vendor/pkg@1.5.0','licenses'=>[['license'=>['id'=>'MIT']]]]]]);
        $report=Assessment::scan($sbom,[$r,$other],['policy'=>['allow'=>['MIT']]]);
        self::assertCount(1,$report['findings']); self::assertSame('high',$report['findings'][0]['severity']['level']);
        self::assertSame(hash('sha256',$sbom),$report['sbomSha256']);self::assertSame(1,Assessment::exitCode($report,true));self::assertSame(0,Assessment::exitCode($report,false));
    }
    public function testMissingIdentityAndUnsupportedVersionRemainUnassessed(): void
    {
        $r=Assessment::scan(Json::encode(['bomFormat'=>'CycloneDX','specVersion'=>'1.6','components'=>[['name'=>'unknown'],['name'=>'branch','purl'=>'pkg:composer/vendor/pkg@dev-main']]]),[]);
        self::assertSame(['unassessed','unassessed'],array_column($r['checks'],'status'));self::assertSame(2,Assessment::exitCode($r,false));
    }
    public function testOsvPaginationDeduplicatesAndDoesNotSendVersions(): void
    {
        $r=$this->record([['introduced'=>'0']]);$calls=[];
        $records=Database::fetch([$this->component(),$this->component('2.0.0')],function(array $body) use (&$calls,$r): array { $calls[]=$body; return isset($body['page_token']) ? ['vulns'=>[$r]] : ['vulns'=>[$r],'next_page_token'=>'next']; });
        self::assertCount(1,$records);self::assertCount(2,$calls);self::assertSame(['package'=>['name'=>'vendor/pkg','ecosystem'=>'Packagist']],$calls[0]);
    }
    public function testRepeatedPaginationTokenStopsAssessment(): void
    {
        $this->expectException(\RuntimeException::class);Database::fetch([$this->component()],static fn(array $body): array => ['next_page_token'=>'same']);
    }
    public function testInvalidDatabaseEventsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);Database::validate([$this->record([['introduced'=>'0','fixed'=>'2.0.0']])]);
    }
}
