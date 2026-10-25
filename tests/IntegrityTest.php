<?php
declare(strict_types=1);
namespace SecuLens\Tests;

use PHPUnit\Framework\TestCase;
use SecuLens\Integrity;
use SecuLens\Sbom;

final class IntegrityTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/seculens-integ-' . bin2hex(random_bytes(6));
        mkdir($this->dir);
    }

    protected function tearDown(): void
    {
        $items = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($items as $f) {
            $f->isDir() && !$f->isLink() ? rmdir($f->getPathname()) : unlink($f->getPathname());
        }
        rmdir($this->dir);
    }

    public function testComputeDependencyDepths(): void
    {
        $components = [
            ['id' => 'root-app', 'name' => 'app'],
            ['id' => 'pkg-a', 'name' => 'a'],
            ['id' => 'pkg-b', 'name' => 'b'],
            ['id' => 'pkg-c', 'name' => 'c'],
        ];
        $dependencies = [
            ['from' => 'root-app', 'to' => 'pkg-a'],
            ['from' => 'pkg-a', 'to' => 'pkg-b'],
            ['from' => 'pkg-b', 'to' => 'pkg-c'],
        ];

        Sbom::computeDependencyDepths($components, $dependencies);

        $lookup = [];
        foreach ($components as $c) { $lookup[$c['id']] = $c['depth'] ?? null; }
        self::assertSame(1, $lookup['pkg-a']);
        self::assertSame(2, $lookup['pkg-b']);
        self::assertSame(3, $lookup['pkg-c']);
    }

    public function testLockfileIntegrityInsecureUrl(): void
    {
        file_put_contents($this->dir . '/package-lock.json', json_encode([
            'packages' => [
                'node_modules/insecure-lib' => [
                    'version' => '1.0.0',
                    'resolved' => 'http://evil-registry.org/insecure-lib-1.0.0.tgz',
                ],
            ],
        ]));

        $sbom = [
            'components' => [['id' => 'c1', 'name' => 'insecure-lib', 'version' => '1.0.0']],
        ];

        $findings = Integrity::checkLockfileIntegrity($this->dir, $sbom);
        self::assertCount(1, $findings);
        self::assertSame('SC-INSECURE-REGISTRY-URL', $findings[0]['ruleId']);
    }

    public function testLockfileIntegrityMismatch(): void
    {
        file_put_contents($this->dir . '/package-lock.json', json_encode([
            'packages' => [
                'node_modules/tampered-pkg' => [
                    'version' => '2.0.0',
                    'integrity' => 'sha512-LOCKFILE_FAKE_HASH_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==',
                ],
            ],
        ]));

        $sbom = [
            'components' => [[
                'id' => 'c1',
                'name' => 'tampered-pkg',
                'version' => '2.0.0',
                'hashes' => [['alg' => 'SHA-512', 'content' => 'SBOM_GENUINE_HASH_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==']],
            ]],
        ];

        $findings = Integrity::checkLockfileIntegrity($this->dir, $sbom);
        self::assertCount(1, $findings);
        self::assertSame('SC-INTEGRITY-MISMATCH', $findings[0]['ruleId']);
    }
}

