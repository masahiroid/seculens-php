<?php
declare(strict_types=1);
use PHPUnit\Framework\TestCase;
use SecuLens\Json;
final class FileSafetyTest extends TestCase
{
    public function testRejectsStreamWrappers(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Json::read('data://text/plain,secret');
    }
    public function testOutputDoesNotFollowSymlink(): void
    {
        $dir = sys_get_temp_dir().'/seculens-safety-'.bin2hex(random_bytes(8)); mkdir($dir,0700);
        try {
            file_put_contents($dir.'/private','DO NOT CHANGE'); symlink($dir.'/private',$dir.'/output');
            Json::write($dir.'/output','report');
            self::assertSame('DO NOT CHANGE',file_get_contents($dir.'/private'));
            self::assertFalse(is_link($dir.'/output'));
            self::assertSame('report',file_get_contents($dir.'/output'));
        } finally { unlink($dir.'/private'); unlink($dir.'/output'); rmdir($dir); }
    }
}
