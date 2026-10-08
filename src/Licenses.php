<?php
declare(strict_types=1);
namespace SecuLens;
use Composer\Spdx\SpdxLicenses;

final class Licenses
{
    private array $tokens = []; private int $position = 0;
    public static function validatePolicy(mixed $p): array
    {
        $p = Json::object($p, 'Policy must be a JSON object');
        foreach (['allow', 'deny'] as $key) {
            foreach (Json::list($p[$key] ?? [], 'Policy allow/deny must be arrays') as $s) { if (!Json::text($s)) { throw new \InvalidArgumentException('Policy entries must be strings'); } }
        }
        return $p;
    }
    public static function evaluate(string $expression, array $policy): string
    {
        if (in_array($expression, ['', 'NONE', 'NOASSERTION'], true)) { return 'review'; }
        $parser = new self();
        try {
            preg_match_all('/\(|\)|[A-Za-z0-9:.+_-]+/', $expression, $matches);
            if (preg_replace('/\s+/', '', $expression) !== implode('', $matches[0]) || count($matches[0]) > 512) { return 'review'; }
            $parser->tokens = $matches[0];
            $node = $parser->expression(0);
            if ($parser->position !== count($parser->tokens)) { return 'review'; }
            return self::decision($node, $policy);
        } catch (\InvalidArgumentException) { return 'review'; }
    }
    private function expression(int $depth): array
    {
        if ($depth > 64) { throw new \InvalidArgumentException('Expression too deep'); }
        $node = $this->and($depth + 1);
        while (($this->tokens[$this->position] ?? '') === 'OR') { $this->position++; $node = ['op'=>'OR','a'=>$node,'b'=>$this->and($depth + 1)]; }
        return $node;
    }
    private function and(int $depth): array
    {
        $node = $this->atom($depth);
        while (($this->tokens[$this->position] ?? '') === 'AND') { $this->position++; $node = ['op'=>'AND','a'=>$node,'b'=>$this->atom($depth)]; }
        return $node;
    }
    private function atom(int $depth): array
    {
        $token = $this->tokens[$this->position++] ?? '';
        if ($token === '(') {
            $node = $this->expression($depth + 1);
            if (($this->tokens[$this->position++] ?? '') !== ')') { throw new \InvalidArgumentException('Unclosed expression'); }
            return $node;
        }
        $spdx = new SpdxLicenses();
        if (!$spdx->getLicenseByIdentifier($token)) { throw new \InvalidArgumentException('Unknown license'); }
        if (($this->tokens[$this->position] ?? '') === 'WITH') {
            $this->position++; $exception = $this->tokens[$this->position++] ?? '';
            if (!$spdx->getExceptionByIdentifier($exception)) { throw new \InvalidArgumentException('Unknown exception'); }
            $token .= ' WITH '.$exception;
        }
        return ['id'=>$token];
    }
    private static function decision(array $node, array $p): string
    {
        if (isset($node['id'])) { return in_array($node['id'], $p['deny'] ?? [], true) ? 'denied' : (in_array($node['id'], $p['allow'] ?? [], true) ? 'allowed' : 'review'); }
        $a = self::decision($node['a'], $p); $b = self::decision($node['b'], $p);
        if ($node['op'] === 'OR') { return $a === 'allowed' || $b === 'allowed' ? 'allowed' : ($a === 'denied' && $b === 'denied' ? 'denied' : 'review'); }
        return $a === 'denied' || $b === 'denied' ? 'denied' : ($a === 'allowed' && $b === 'allowed' ? 'allowed' : 'review');
    }
    public static function findings(array $c, array $p): array
    {
        $out = [];
        foreach ($c['licenses'] ?: ['NOASSERTION'] as $expression) {
            $state = self::evaluate($expression, $p);
            if ($state === 'allowed') { continue; }
            $denied = $state === 'denied';
            $out[] = ['category'=>'license','ruleId'=>$denied ? 'LICENSE-DENIED' : 'LICENSE-REVIEW','subject'=>$c['id'],'status'=>$state,'summary'=>$denied ? 'License denied by policy' : 'License requires review','evidence'=>$expression,'recommendation'=>'Confirm the license, usage and distribution conditions against the customer policy.'];
        }
        return $out;
    }
}
