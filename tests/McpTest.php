<?php
declare(strict_types=1);
namespace SecuLens\Tests;

use PHPUnit\Framework\TestCase;
use SecuLens\Mcp;

final class McpTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        $this->root = dirname(__DIR__);
    }

    public function testInitialize(): void
    {
        $res = Mcp::handleRequest([
            'jsonrpc' => '2.0',
            'id' => 1,
            'method' => 'initialize',
            'params' => [
                'protocolVersion' => '2024-11-05',
                'clientInfo' => ['name' => 'test-client'],
            ],
        ]);

        self::assertSame(1, $res['id']);
        self::assertSame('2024-11-05', $res['result']['protocolVersion']);
        self::assertSame('seculens-php', $res['result']['serverInfo']['name']);
    }

    public function testToolsList(): void
    {
        $res = Mcp::handleRequest([
            'jsonrpc' => '2.0',
            'id' => 2,
            'method' => 'tools/list',
        ]);

        self::assertSame(2, $res['id']);
        $names = array_column($res['result']['tools'], 'name');
        self::assertContains('seculens_scan', $names);
        self::assertContains('seculens_analyze', $names);
        self::assertContains('seculens_check_license', $names);
        self::assertContains('seculens_generate_report', $names);
    }

    public function testCheckLicense(): void
    {
        $res = Mcp::handleRequest([
            'jsonrpc' => '2.0',
            'id' => 3,
            'method' => 'tools/call',
            'params' => [
                'name' => 'seculens_check_license',
                'arguments' => [
                    'expression' => 'MIT OR Apache-2.0',
                    'allow' => ['MIT'],
                ],
            ],
        ]);

        self::assertSame(3, $res['id']);
        self::assertFalse($res['result']['isError']);
        $data = json_decode($res['result']['content'][0]['text'], true);
        self::assertSame('allowed', $data['status']);
    }

    public function testScanOffline(): void
    {
        $res = Mcp::handleRequest([
            'jsonrpc' => '2.0',
            'id' => 4,
            'method' => 'tools/call',
            'params' => [
                'name' => 'seculens_scan',
                'arguments' => [
                    'sbomPath' => $this->root . '/examples/cyclonedx.json',
                    'dbPath' => $this->root . '/examples/database.json',
                    'policy' => ['allow' => ['MIT', 'Apache-2.0']],
                ],
            ],
        ]);

        self::assertSame(4, $res['id']);
        self::assertFalse($res['result']['isError']);
        $data = json_decode($res['result']['content'][0]['text'], true);
        self::assertGreaterThan(0, $data['summary']['components']);
        self::assertIsArray($data['findings']);
    }
}
