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

    private static function shared(): array
    {
        return json_decode((string)file_get_contents(__DIR__.'/fixtures/supply-chain.json'), true, 512, JSON_THROW_ON_ERROR);
    }

    public static function integrityCases(): iterable
    {
        foreach (self::shared()['integrity'] as $case) { yield $case['name'] => [$case]; }
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('integrityCases')]
    public function testSharedIntegrityFixture(array $case): void
    {
        foreach ($case['files'] as $name => $content) {
            file_put_contents($this->dir.'/'.$name, is_string($content) ? $content : json_encode($content, JSON_UNESCAPED_SLASHES));
        }
        self::assertSame($case['expected'], Integrity::checkLockfileIntegrity($this->dir, ['components' => $case['components']]));
    }

    public function testLockfileIntegrityMissingDirectory(): void
    {
        self::assertSame([], Integrity::checkLockfileIntegrity($this->dir.'/missing', ['components' => []]));
    }

    public function testSharedCoolOffFixture(): void
    {
        $f = self::shared()['coolOff'];
        self::assertSame($f['expected'], Integrity::coolOffFindings($f['components'], $f['published'], $f['minDays'], new \DateTimeImmutable($f['now'])));
    }

    public function testSharedCoolOffDayLimits(): void
    {
        $f = self::shared()['coolOff'];
        foreach ($f['validDays'] as $value) { self::assertSame((int)$value, Integrity::parseCoolOffDays($value)); }
        foreach ($f['invalidDays'] as $value) {
            try { Integrity::parseCoolOffDays($value); self::fail('Accepted '.var_export($value, true)); }
            catch (\InvalidArgumentException $e) { self::assertStringContainsString('Cool-off must be a whole number', $e->getMessage()); }
        }
    }

    public function testCheckPackageCoolOffUsesInjectedLookup(): void
    {
        $f = self::shared()['coolOff']; $seen = [];
        $findings = Integrity::checkPackageCoolOff($f['components'], 7, new \DateTimeImmutable($f['now']), static function (array $c) use (&$seen, $f): array { $seen[] = count($c); return $f['published']; });
        self::assertSame($f['expected'], $findings);
        self::assertSame([count($f['components'])], $seen);
    }

    public function testFetchReleaseDatesQueriesEachRegistryOnce(): void
    {
        $urls = [];
        $get = static function (string $url) use (&$urls): mixed {
            $urls[] = $url;
            if (str_contains($url, 'missing')) { return null; }
            if (str_starts_with($url, 'https://registry.npmjs.org/')) { return ['time' => ['1.0.0' => '2026-11-14T00:00:00Z', '1.1.0' => '2026-11-15T00:00:00Z']]; }
            if (str_starts_with($url, 'https://pypi.org/')) { return ['urls' => [['upload_time_iso_8601' => '2026-11-16T02:00:00Z'], ['upload_time_iso_8601' => '2026-11-16T01:00:00Z']]]; }
            return ['packages' => ['acme/lib' => [['version' => 'v1.2.0', 'time' => '2026-11-13T00:00:00+00:00'], ['version' => 'v1.1.0']]]];
        };
        $c = static fn(string $n, string $v, string $e): array => ['name' => $n, 'version' => $v, 'ecosystem' => $e];
        $dates = Integrity::fetchReleaseDates([$c('@scope/pkg', '1.0.0', 'npm'), $c('@scope/pkg', '1.1.0', 'npm'), $c('Requests', '2.40.0', 'PyPI'), $c('acme/lib', '1.2.0', 'Packagist'), $c('acme/lib', '1.1.0', 'Packagist'), $c('missing', '1.0.0', 'npm'), $c('lib', '1.0.0', 'Maven')], $get);
        self::assertSame([
            'npm' => ['@scope/pkg@1.0.0' => '2026-11-14T00:00:00Z', '@scope/pkg@1.1.0' => '2026-11-15T00:00:00Z'],
            'PyPI' => ['Requests@2.40.0' => '2026-11-16T01:00:00Z'],
            'Packagist' => ['acme/lib@1.2.0' => '2026-11-13T00:00:00+00:00', 'acme/lib@1.1.0' => '2026-11-13T00:00:00+00:00'],
        ], $dates);
        self::assertSame(['https://registry.npmjs.org/@scope%2Fpkg', 'https://pypi.org/pypi/Requests/2.40.0/json', 'https://repo.packagist.org/p2/acme/lib.json', 'https://registry.npmjs.org/missing'], $urls);
    }

    public function testExpandPackagistVersionsHonoursUnset(): void
    {
        self::assertSame(
            [['version' => '2.0.0', 'time' => 't2', 'license' => ['MIT']], ['version' => '1.0.0', 'time' => 't2']],
            Integrity::expandPackagistVersions([['version' => '2.0.0', 'time' => 't2', 'license' => ['MIT']], ['version' => '1.0.0', 'license' => '__unset']]),
        );
    }
}
