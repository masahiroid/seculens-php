<?php
declare(strict_types=1);
namespace SecuLens\Tests;
use PHPUnit\Framework\TestCase;
use SecuLens\Wizard;

final class WizardTest extends TestCase
{
    private function simulate(string $input,?string $lang=null): array
    {
        $stream=fopen('php://memory','r+');fwrite($stream,$input);rewind($stream);$output='';
        $wizard=new Wizard($stream,static function(string $s,bool $newline) use (&$output): void { $output.=$s.($newline?"\n":''); });
        try { return [$wizard->settings($lang),$output]; } finally { fclose($stream); }
    }
    public function testEofCancelsWithoutAcceptingStart(): void
    {
        [$o,$text]=$this->simulate('');self::assertNull($o);self::assertStringContainsString('Cancelled',$text);
        [$o,$text]=$this->simulate('', 'ja');self::assertNull($o);self::assertStringContainsString('中止しました',$text);
    }
    public function testEnglishDefaultsAndCustomerLayout(): void
    {
        [$o,$text]=$this->simulate("\n\n\n\n\n\n\n\n\n\n\n\n\ny\n");
        self::assertNotNull($o);self::assertSame('en',$o['lang']);self::assertSame('customer',$o['report-style']);self::assertFalse($o['fetch-osv']);self::assertFalse($o['fail-on-findings']);
    }
    public function testOnlineDisclosureAndJapaneseSelection(): void
    {
        [$o,$text]=$this->simulate("ja\n1\nbom.json\nyes\n\n\n顧客\n対象\n作成者\ncustomer\nreports\nno\nyes\n");
        self::assertNotNull($o);self::assertSame('ja',$o['lang']);self::assertTrue($o['fetch-osv']);self::assertStringContainsString('api.osv.dev',$text);self::assertSame('顧客',$o['customer']);
    }
    public function testDeclinedConfirmationCancels(): void
    {
        [$o,$text]=$this->simulate("2\n.\nspdx\nbom.json\nsyft\nn\n",'en');self::assertNull($o);self::assertStringContainsString('Cancelled',$text);
    }
    public function testGenerateSettingsAndInvalidChoiceRetry(): void
    {
        [$o,$text]=$this->simulate("bad\n2\n.\nspdx\nbom.json\nsyft\ny\n",'ja');self::assertSame('sbom',$o['operation']);self::assertSame('spdx',$o['format']);self::assertStringContainsString('再入力',$text);
    }
}
