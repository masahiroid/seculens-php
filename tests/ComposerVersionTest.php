<?php
declare(strict_types=1);
namespace SecuLens\Tests;

use PHPUnit\Framework\TestCase;
use SecuLens\Matcher;
use SecuLens\Versions;

final class ComposerVersionTest extends TestCase
{
    public function testSharedFixtures(): void
    {
        $cases=json_decode(file_get_contents(__DIR__.'/fixtures/composer-versions.json'),true,16,JSON_THROW_ON_ERROR);
        foreach ($cases as $c) {
            self::assertSame($c['expected'],Versions::compare($c['a'],$c['b'],'Packagist'),$c['a'].' vs '.$c['b']);
            if ($c['expected']!==null) { self::assertSame(-$c['expected'],Versions::compare($c['b'],$c['a'],'Packagist'),$c['b'].' vs '.$c['a']); }
        }
    }

    public function testPackagistRangesUseComposerStabilityOrder(): void
    {
        $record=['id'=>'X','affected'=>[['package'=>['name'=>'acme/lib','ecosystem'=>'Packagist'],'ranges'=>[['type'=>'ECOSYSTEM','events'=>[['introduced'=>'0'],['fixed'=>'2.0.0-RC1']]]]]]];
        $at=static fn(string $v): string => Matcher::match(['name'=>'acme/lib','ecosystem'=>'Packagist','version'=>$v],$record);
        self::assertSame('affected',$at('2.0.0-beta3'));
        self::assertSame('not-affected',$at('2.0.0-RC1'));
        self::assertSame('affected',$at('1.9.9.1'));
        self::assertSame('unknown',$at('2.x-dev'));
    }
}
