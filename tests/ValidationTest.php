<?php
declare(strict_types=1);
namespace SecuLens\Tests;

use PHPUnit\Framework\TestCase;
use SecuLens\Validation;
use SecuLens\Assessment;
use SecuLens\Json;

final class ValidationTest extends TestCase
{
    public function testSharedFixtures(): void
    {
        $cases=json_decode(file_get_contents(__DIR__.'/fixtures/validation.json'),false,128,JSON_THROW_ON_ERROR);
        foreach ($cases as $case) {
            $result=Validation::validate($case->input,$case->kind);
            self::assertSame($case->valid,$result['valid'],$case->name.': '.json_encode($result));
            self::assertSame($case->valid,$result['errors']===[]);
        }
    }
    public function testReportAndCli(): void
    {
        $root=dirname(__DIR__);
        $result=[]; $status=0;
        exec(escapeshellarg(PHP_BINARY).' '.escapeshellarg($root.'/bin/seculens').' validate '.escapeshellarg($root.'/examples/cyclonedx.json'),$result,$status);
        self::assertSame(0,$status); self::assertTrue(json_decode(implode("\n",$result),true)['valid']);
        $result=[];
        exec(escapeshellarg(PHP_BINARY).' '.escapeshellarg($root.'/bin/seculens').' validate '.escapeshellarg($root.'/examples/policy.json'),$result,$status);
        self::assertSame(2,$status); self::assertFalse(json_decode(implode("\n",$result),true)['valid']);
    }
}
