<?php
declare(strict_types=1);
namespace SecuLens\Tests;
use PHPUnit\Framework\TestCase;
use SecuLens\Analysis;

final class AnalysisTest extends TestCase
{
    private string $directory;
    protected function setUp(): void { $this->directory=sys_get_temp_dir().'/seculens-ast-'.bin2hex(random_bytes(6));mkdir($this->directory); }
    protected function tearDown(): void
    {
        $items=new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->directory,\FilesystemIterator::SKIP_DOTS),\RecursiveIteratorIterator::CHILD_FIRST);
        foreach($items as $file) { is_dir($file->getPathname()) && !is_link($file->getPathname()) ? rmdir($file->getPathname()) : unlink($file->getPathname()); }rmdir($this->directory);
    }
    public function testDangerousConstructsAndFunctionAliasesWithoutExecution(): void
    {
        $code=<<<'PHP'
<?php
namespace Example;
use function shell_exec as run;
file_put_contents(__DIR__.'/executed', 'should never run');
function sample($input,$db) {
    eval($input); run($input); \system($input); unserialize($input);
    include $input; $db->query('SELECT '.$input); md5($input);
    return `echo $input`;
}
\Other\shell_exec('custom');
PHP;
        file_put_contents($this->directory.'/input.php',$code);
        $r=Analysis::scan($this->directory);$ids=array_column($r['findings'],'ruleId');
        self::assertContains('PHP-EVAL',$ids);self::assertContains('PHP-UNSERIALIZE',$ids);self::assertContains('PHP-DYNAMIC-SQL',$ids);self::assertContains('PHP-DYNAMIC-INCLUDE',$ids);self::assertContains('PHP-WEAK-HASH',$ids);
        self::assertCount(3,array_filter($ids,static fn(string $id): bool=>$id==='PHP-SHELL'));
        self::assertFileDoesNotExist($this->directory.'/executed');self::assertSame(1,$r['metadata']['filesParsed']);
    }
    public function testSyntaxErrorsAndEmptyTreesAreCoverageFindings(): void
    {
        file_put_contents($this->directory.'/broken.php','<?php function {');
        $r=Analysis::scan($this->directory);self::assertSame('coverage',$r['findings'][0]['category']);self::assertSame(0,$r['metadata']['filesParsed']);
        unlink($this->directory.'/broken.php');self::assertSame('PHP-NO-FILES',Analysis::scan($this->directory)['findings'][0]['ruleId']);
    }
    public function testVendorAndSymlinksAreSkipped(): void
    {
        mkdir($this->directory.'/vendor');file_put_contents($this->directory.'/vendor/danger.php','<?php eval($x);');
        file_put_contents($this->directory.'/safe.php','<?php function safe(){ return 1; }');symlink($this->directory.'/vendor/danger.php',$this->directory.'/linked.php');
        $r=Analysis::scan($this->directory);self::assertSame(1,$r['metadata']['filesDiscovered']);self::assertSame([],$r['findings']);
    }
    public function testNestedFunctionsHaveIndependentComplexity(): void
    {
        $code='<?php function outer() { $inner = function($a) {'.str_repeat('if($a){ $a++; }',11).'}; return $inner; }';
        file_put_contents($this->directory.'/complex.php',$code);$r=Analysis::scan($this->directory);
        self::assertCount(1,$r['findings']);self::assertStringContainsString('closure; cyclomatic complexity 12',$r['findings'][0]['evidence']);
    }
    public function testNestingAndBooleanOperatorsCount(): void
    {
        file_put_contents($this->directory.'/nested.php','<?php function nested($a) { if($a){while($a){for(;;){foreach([] as $x){if($x){return 1;}}}}} }');
        $r=Analysis::scan($this->directory);self::assertStringContainsString('maximum nesting 5',$r['findings'][0]['evidence']);
        file_put_contents($this->directory.'/boolean.php','<?php function logical($a) {return '.implode(' && ',array_fill(0,12,'$a')).';}');
        $r=Analysis::scan($this->directory);self::assertCount(2,$r['findings']);
    }
    public function testSafeLiteralsAndQualifiedFunctionsAvoidCandidates(): void
    {
        file_put_contents($this->directory.'/safe.php',"<?php namespace App; include 'config.php'; \\App\\md5('x'); \\App\\exec('x');");
        self::assertSame([],Analysis::scan($this->directory)['findings']);
    }
}
