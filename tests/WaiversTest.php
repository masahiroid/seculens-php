<?php
declare(strict_types=1);
namespace SecuLens\Tests;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SecuLens\{Json,Mcp,Runner,Validation,Waivers};
use Symfony\Component\Process\Process;

final class WaiversTest extends TestCase
{
    private static function fixture(bool $objects = false): mixed
    {
        return json_decode(Json::read(__DIR__.'/fixtures/waivers.json'), !$objects, 128, JSON_THROW_ON_ERROR);
    }
    public static function cases(): array
    {
        $cases = [];
        foreach (self::fixture()['cases'] as $case) { $cases[$case['name']] = [$case]; }
        return $cases;
    }
    #[DataProvider('cases')]
    public function testSharedWaiverCases(array $case): void
    {
        self::assertEquals($case['expected'], Waivers::apply($case['findings'], $case['waivers'], $case['date']));
    }
    public function testValidWaiverFiles(): void
    {
        foreach (self::fixture(true)->valid as $data) {
            self::assertEquals(json_decode(json_encode($data), true), Waivers::validate($data));
            self::assertTrue(Validation::validate($data, 'waivers')['valid']);
        }
    }
    public function testInvalidWaiverFiles(): void
    {
        foreach (self::fixture(true)->invalid as $data) {
            try { Waivers::validate($data); self::fail('Accepted '.json_encode($data)); }
            catch (\InvalidArgumentException $e) { self::assertStringContainsString('Waiver', $e->getMessage()); }
            self::assertFalse(Validation::validate($data, 'waivers')['valid'], json_encode($data));
        }
    }
    public function testInvalidEvaluationDate(): void
    {
        $this->expectExceptionMessage('Waiver');
        Waivers::apply([], [], '2026-13-01');
    }
    private static function waiverFile(string $expires): array
    {
        $entry = static fn(string $rule): array => ['ruleId'=>$rule,'justification'=>'Demo package is not shipped','approvedBy'=>'Security team','expires'=>$expires];
        return ['schemaVersion'=>'1.0','waivers'=>[$entry('SECULENS-DEMO-NPM'),$entry('SECULENS-DEMO-PYPI'),$entry('SECULENS-DEMO-PHP')]];
    }
    public function testCliWaiverKeepsFindingAndClearsExitCode(): void
    {
        $directory = sys_get_temp_dir().'/seculens-waiver-'.bin2hex(random_bytes(6)); mkdir($directory);
        $root = dirname(__DIR__);
        try {
            file_put_contents($directory.'/waivers.json', json_encode(self::waiverFile('2999-12-31')));
            $options = ['sbom'=>$root.'/examples/cyclonedx.json','db'=>$root.'/examples/database.json','waivers'=>$directory.'/waivers.json','fail-on-findings'=>true,'output'=>$directory.'/out'];
            $result = Runner::scan($options);
            self::assertSame(0, $result['exitCode']);
            $report = json_decode(Json::read($directory.'/out/report.json'), false, 128, JSON_THROW_ON_ERROR);
            self::assertSame('1.3', $report->schemaVersion);
            self::assertTrue(Validation::validate($report, 'report')['valid']);
            $vulnerability = array_values(array_filter($report->findings, static fn($f): bool => $f->category === 'vulnerability'))[0];
            self::assertSame('affected', $vulnerability->status);
            self::assertSame('waivers[0]', $vulnerability->waiver->source);
            $report->schemaVersion = '1.2';
            self::assertFalse(Validation::validate($report, 'report')['valid']);
            foreach ($report->findings as $f) { unset($f->waiver); }
            self::assertTrue(Validation::validate($report, 'report')['valid']);
            file_put_contents($directory.'/waivers.json', json_encode(self::waiverFile('2000-01-01')));
            $expired = Runner::scan($options);
            self::assertSame(1, $expired['exitCode']);
            self::assertContains('WAIVER-EXPIRED', array_column($expired['report']['findings'], 'ruleId'));
            file_put_contents($directory.'/waivers.json', '{"schemaVersion":"1.0","waivers":{}}');
            $process = new Process([PHP_BINARY,$root.'/bin/seculens','scan',$options['sbom'],'--db',$options['db'],'--waivers',$directory.'/waivers.json','--output',$directory.'/bad']);
            $process->run();
            self::assertSame(2, $process->getExitCode());
            self::assertStringContainsString('waivers must be an array', $process->getOutput().$process->getErrorOutput());
        } finally {
            $items = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($directory, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
            foreach ($items as $file) { $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname()); }
            rmdir($directory);
        }
    }
    public function testMcpScanAppliesWaivers(): void
    {
        $root = dirname(__DIR__);
        $call = static fn(array $arguments): array => Mcp::handleRequest(['jsonrpc'=>'2.0','id'=>1,'method'=>'tools/call','params'=>['name'=>'seculens_scan','arguments'=>$arguments]])['result'];
        $ok = $call(['sbomPath'=>$root.'/examples/cyclonedx.json','dbPath'=>$root.'/examples/database.json','waivers'=>self::waiverFile('2999-12-31')]);
        $body = json_decode($ok['content'][0]['text'], true);
        self::assertSame(3, $body['summary']['waived']);
        self::assertSame(0, $body['summary']['affectedVulnerabilities']);
        self::assertTrue($call(['sbomPath'=>$root.'/examples/cyclonedx.json','waivers'=>['waivers'=>[]]])['isError']);
    }
}
