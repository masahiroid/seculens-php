<?php
declare(strict_types=1);
namespace SecuLens\Tests;

use PHPUnit\Framework\TestCase;
use SecuLens\Assessment;
use SecuLens\Cvss4;
use SecuLens\Priority;
use SecuLens\Validation;

final class PriorityTest extends TestCase
{
    private static function load(string $name): array { return json_decode(file_get_contents(__DIR__.'/fixtures/'.$name),true,64,JSON_THROW_ON_ERROR); }
    private static function vulnerability(array $report): array { return array_values(array_filter($report['findings'],static fn(array $f): bool => $f['category']==='vulnerability'))[0]; }
    private static function scan(array $policy): array { $s=self::load('priority.json')['scan']; return Assessment::scan(json_encode($s['sbom'],JSON_THROW_ON_ERROR),$s['records'],['policy'=>$policy]); }

    public function testPublishedAndGeneratedVectors(): void
    {
        $v=self::load('cvss4-vectors.json');
        foreach ([...$v['published'],...$v['generated']] as $c) { self::assertEqualsWithDelta($c['score'],Cvss4::score($c['vector']),0.0001,$c['vector']); }
    }
    public function testRejectsInvalidVectors(): void
    {
        foreach ([...self::load('cvss4-vectors.json')['invalid'],null] as $vector) { self::assertNull(Cvss4::score($vector)); }
    }
    public function testEveryBaseCombinationMatchesSharedDigest(): void
    {
        $v=self::load('cvss4-vectors.json'); $keys=array_keys($v['baseMetrics']); $hash=hash_init('sha256'); $count=0;
        $walk=function (int $i,array $parts) use (&$walk,&$hash,&$count,$keys,$v): void {
            if ($i===count($keys)) { $vector='CVSS:4.0/'.implode('/',$parts); hash_update($hash,$vector.' '.number_format(Cvss4::score($vector),1,'.','')."\n"); $count++; return; }
            foreach ($v['baseMetrics'][$keys[$i]] as $value) { $walk($i+1,[...$parts,$keys[$i].':'.$value]); }
        };
        $walk(0,[]);
        self::assertSame($v['baseVectors']['count'],$count);
        self::assertSame($v['baseVectors']['sha256'],hash_final($hash));
    }
    public function testPriorityCases(): void
    {
        foreach (self::load('priority.json')['cases'] as $c) { self::assertSame($c['expected'],Priority::component($c['severity'],$c['component'],$c['context']),$c['name']); }
    }
    public function testRejectsInvalidContext(): void
    {
        foreach (self::load('priority.json')['invalidContexts'] as $context) {
            try { Priority::validateContext($context); self::fail(json_encode($context)); }
            catch (\InvalidArgumentException $e) { self::assertStringContainsString('Policy',$e->getMessage()); }
        }
    }
    public function testScanScoresCvss4AndPrioritizesAgainstSchema(): void
    {
        $s=self::load('priority.json')['scan'];
        $report=self::scan($s['policy']); $f=self::vulnerability($report);
        self::assertSame($s['expected']['severity']['level'],$f['severity']['level']);
        self::assertEqualsWithDelta($s['expected']['severity']['score'],$f['severity']['score'],0.0001);
        self::assertSame($s['expected']['priority'],$f['priority']);
        self::assertTrue(Validation::validate(json_decode(json_encode($report,JSON_THROW_ON_ERROR),false,128,JSON_THROW_ON_ERROR),'report')['valid']);
        self::assertArrayNotHasKey('priority',self::vulnerability(self::scan([])));
        $this->expectException(\InvalidArgumentException::class);
        self::scan(['context'=>['foo'=>1]]);
    }
    public function testKeepsAcceptingSchema11Reports(): void
    {
        $report=self::scan(self::load('priority.json')['scan']['policy']); $report['schemaVersion']='1.1';
        $encode=static fn(array $r): object => json_decode(json_encode($r,JSON_THROW_ON_ERROR),false,128,JSON_THROW_ON_ERROR);
        $result=Validation::validate($encode($report),'report');
        self::assertSame('report-1.1.schema.json',$result['schema']); self::assertFalse($result['valid']);
        foreach ($report['findings'] as $i=>$f) { unset($report['findings'][$i]['priority']); }
        self::assertTrue(Validation::validate($encode($report),'report')['valid']);
    }
}
