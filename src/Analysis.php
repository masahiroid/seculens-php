<?php
declare(strict_types=1);
namespace SecuLens;
use PhpParser\Error;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\ParserFactory;

final class Analysis
{
    private const SKIP = ['vendor','node_modules','.git','.venv','venv','dist','build','reports','releases','.phpunit.cache'];
    public static function scan(string $target): array
    {
        if (is_link($target) || (!is_dir($target) && !is_file($target))) { throw new \InvalidArgumentException('Source must be a readable file or directory, not a symlink'); }
        $root = realpath(is_dir($target) ? $target : dirname($target));
        if ($root === false) { throw new \RuntimeException('Cannot resolve source path'); }
        $files = [];
        if (is_file($target)) {
            if (strtolower(pathinfo($target, PATHINFO_EXTENSION)) !== 'php') { throw new \InvalidArgumentException('Source file must be PHP'); }
            $files[] = realpath($target);
        } else {
            $walk = function (string $directory) use (&$walk, &$files): void {
                $items = scandir($directory);
                if ($items === false) { throw new \RuntimeException("Cannot read source directory: $directory"); }
                foreach ($items as $name) {
                    if ($name === '.' || $name === '..') { continue; }
                    $path = $directory.DIRECTORY_SEPARATOR.$name;
                    if (is_link($path)) { continue; }
                    if (is_dir($path)) { if (!in_array($name, self::SKIP, true)) { $walk($path); } }
                    elseif (strtolower(pathinfo($path, PATHINFO_EXTENSION)) === 'php') { $files[] = $path; }
                }
            };
            $walk($root);
        }
        sort($files, SORT_STRING); $findings = []; $parsed = 0;
        $parser = (new ParserFactory())->createForNewestSupportedVersion();
        foreach ($files as $path) {
            $relative = str_replace(DIRECTORY_SEPARATOR, '/', substr($path, strlen($root) + 1));
            try {
                $nodes = $parser->parse(Json::read($path)) ?? [];
                $names = new NodeTraverser(); $names->addVisitor(new NameResolver(null, ['preserveOriginalNames'=>true]));
                $nodes = $names->traverse($nodes);
                $visitor = new ReviewVisitor($relative);
                $traverser = new NodeTraverser(); $traverser->addVisitor($visitor); $traverser->traverse($nodes);
                array_push($findings, ...$visitor->findings); $parsed++;
            } catch (Error $e) {
                $findings[] = self::coverage($relative, 'PHP-SYNTAX', $e->getRawMessage(), max(1, $e->getStartLine()));
            }
        }
        if (!$files) { $findings[] = self::coverage($target, 'PHP-NO-FILES', 'No PHP source files found', 1); }
        if (is_dir($root)) {
            array_push($findings, ...self::checkLifecycleScripts($root));
        }
        usort($findings, static fn(array $a, array $b): int => [$a['file'],$a['line'],$a['ruleId']] <=> [$b['file'],$b['line'],$b['ruleId']]);
        return ['findings'=>$findings,'metadata'=>['language'=>'PHP','target'=>$target,'filesDiscovered'=>count($files),'filesParsed'=>$parsed]];
    }
    public static function checkLifecycleScripts(string $root): array
    {
        $findings = [];
        $composerFile = $root . DIRECTORY_SEPARATOR . 'composer.json';
        if (is_file($composerFile)) {
            try {
                $data = json_decode(file_get_contents($composerFile) ?: '', true);
                if (is_array($data) && isset($data['scripts']) && is_array($data['scripts'])) {
                    $hooks = ['pre-install-cmd', 'post-install-cmd', 'pre-update-cmd', 'post-update-cmd', 'pre-autoload-dump', 'post-autoload-dump'];
                    foreach ($hooks as $hook) {
                        if (isset($data['scripts'][$hook])) {
                            $cmd = is_array($data['scripts'][$hook]) ? implode('; ', $data['scripts'][$hook]) : (string)$data['scripts'][$hook];
                            if (trim($cmd) !== '') {
                                $findings[] = [
                                    'category' => 'security',
                                    'ruleId' => 'SC-LIFECYCLE-SCRIPT',
                                    'subject' => 'composer.json',
                                    'status' => 'review',
                                    'summary' => "Lifecycle script '{$hook}' detected in root composer.json",
                                    'evidence' => "\"{$hook}\": \"{$cmd}\"",
                                    'recommendation' => 'Review lifecycle scripts or execute with --no-scripts to prevent arbitrary command execution.',
                                    'file' => 'composer.json',
                                    'line' => 1,
                                ];
                            }
                        }
                    }
                }
            } catch (\Throwable) {}
        }
        $pkgFile = $root . DIRECTORY_SEPARATOR . 'package.json';
        if (is_file($pkgFile)) {
            try {
                $data = json_decode(file_get_contents($pkgFile) ?: '', true);
                if (is_array($data) && isset($data['scripts']) && is_array($data['scripts'])) {
                    $hooks = ['preinstall', 'install', 'postinstall', 'preuninstall', 'postuninstall'];
                    foreach ($hooks as $hook) {
                        if (isset($data['scripts'][$hook]) && is_string($data['scripts'][$hook]) && trim($data['scripts'][$hook]) !== '') {
                            $findings[] = [
                                'category' => 'security',
                                'ruleId' => 'SC-LIFECYCLE-SCRIPT',
                                'subject' => 'package.json',
                                'status' => 'review',
                                'summary' => "Lifecycle script '{$hook}' detected in package.json",
                                'evidence' => "\"{$hook}\": \"{$data['scripts'][$hook]}\"",
                                'recommendation' => 'Review the lifecycle script or install with --ignore-scripts to avoid arbitrary command execution.',
                                'file' => 'package.json',
                                'line' => 1,
                            ];
                        }
                    }
                }
            } catch (\Throwable) {}
        }
        $lockFile = $root . DIRECTORY_SEPARATOR . 'package-lock.json';
        if (is_file($lockFile)) {
            try {
                $lock = json_decode(file_get_contents($lockFile) ?: '', true);
                if (is_array($lock) && isset($lock['packages']) && is_array($lock['packages'])) {
                    foreach ($lock['packages'] as $pkgPath => $pkgVal) {
                        if ($pkgPath === '' || !is_array($pkgVal)) { continue; }
                        if (!empty($pkgVal['hasInstallScript'])) {
                            $parts = explode('node_modules/', (string)$pkgPath);
                            $name = end($parts);
                            $findings[] = [
                                'category' => 'security',
                                'ruleId' => 'SC-LIFECYCLE-SCRIPT',
                                'subject' => $name,
                                'status' => 'review',
                                'summary' => "Dependency has install script: {$name}",
                                'evidence' => "hasInstallScript: true (version: " . ($pkgVal['version'] ?? 'unknown') . ")",
                                'recommendation' => 'Review the package installation scripts or use --ignore-scripts.',
                                'file' => 'package-lock.json',
                                'line' => 1,
                            ];
                        }
                    }
                }
            } catch (\Throwable) {}
        }
        return $findings;
    }
    private static function coverage(string $file, string $rule, string $evidence, int $line): array
    {
        return ['category'=>'coverage','ruleId'=>$rule,'subject'=>$file,'status'=>'unassessed','summary'=>'PHP source could not be fully assessed','evidence'=>$evidence,'recommendation'=>'Fix syntax or provide readable PHP source and repeat the assessment.','file'=>$file,'line'=>$line];
    }
}

/** Scope stack keeps nested functions independent of their enclosing function. */
final class ReviewVisitor extends NodeVisitorAbstract
{
    public array $findings = [];
    private array $scopes = [];
    public function __construct(private readonly string $file) {}
    public function enterNode(Node $node): ?int
    {
        if ($node instanceof Node\FunctionLike) {
            $this->scopes[] = ['node'=>$node,'complexity'=>1,'depth'=>0,'maxDepth'=>0];
        }
        $index = count($this->scopes) - 1;
        if ($index >= 0) {
            if (self::decision($node)) { $this->scopes[$index]['complexity']++; }
            if (self::nested($node)) { $this->scopes[$index]['depth']++; $this->scopes[$index]['maxDepth'] = max($this->scopes[$index]['maxDepth'], $this->scopes[$index]['depth']); }
        }
        if ($node instanceof Node\Expr\Eval_) { $this->add($node, 'PHP-EVAL', 'Dynamic PHP evaluation', 'eval'); }
        elseif ($node instanceof Node\Expr\ShellExec) { $this->add($node, 'PHP-SHELL', 'Shell execution requires review', 'Backtick shell execution'); }
        elseif ($node instanceof Node\Expr\Include_ && !$node->expr instanceof Node\Scalar\String_) { $this->add($node, 'PHP-DYNAMIC-INCLUDE', 'Dynamic include or require path', 'Nonliteral include/require expression'); }
        elseif ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
            $name = strtolower($node->name->toString());
            // Qualified user functions are not treated as global builtins. Unqualified namespace calls can fall back to globals.
            if ($node->name->isUnqualified() || $node->name instanceof Node\Name\FullyQualified && !str_contains($name, '\\')) {
                if (in_array($name, ['exec','system','shell_exec','passthru','popen','proc_open'], true)) { $this->add($node, 'PHP-SHELL', 'Shell execution requires review', $name); }
                if ($name === 'getenv') { $this->add($node, 'PHP-PROCESS-ENV', 'Environment variable access requires review', $name); }
                if ($name === 'unserialize') { $this->add($node, 'PHP-UNSERIALIZE', 'Deserialization requires review', 'unserialize; inspect input trust and allowed_classes'); }
                if (in_array($name, ['md5','sha1'], true)) { $this->add($node, 'PHP-WEAK-HASH', 'Hash use requires context review', $name.' is unsuitable for password storage or collision-resistant security uses'); }
            }
        } elseif ($node instanceof Node\Expr\Variable && is_string($node->name) && in_array($node->name, ['_ENV','_SERVER'], true)) {
            $this->add($node, 'PHP-PROCESS-ENV', 'Environment variable access requires review', '$'.$node->name);
        } elseif ($node instanceof Node\Scalar\String_ && preg_match('/(?:\/\.ssh|\/\.aws|\/\.npmrc|\/\.composer|id_rsa|id_ed25519)/', $node->value)) {
            $this->add($node, 'PHP-SENSITIVE-PATH', 'Sensitive credential path reference requires review', $node->value);
        } elseif (($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall) && $node->name instanceof Node\Identifier && in_array(strtolower($node->name->toString()), ['query','exec'], true)) {
            $args = $node->getArgs();
            if (isset($args[0]) && ($args[0]->value instanceof Node\Expr\BinaryOp\Concat || $args[0]->value instanceof Node\Scalar\InterpolatedString)) { $this->add($node, 'PHP-DYNAMIC-SQL', 'Constructed query requires review', 'Concatenated or interpolated argument to query/exec; receiver type is not resolved'); }
        }
        return null;
    }
    public function leaveNode(Node $node): ?int
    {
        $index = count($this->scopes) - 1;
        if ($index >= 0 && self::nested($node)) { $this->scopes[$index]['depth']--; }
        if ($node instanceof Node\FunctionLike) {
            $scope = array_pop($this->scopes);
            if ($scope['complexity'] > 10 || $scope['maxDepth'] > 4) {
                $name = isset($node->name) ? $node->name->toString() : ($node instanceof Node\Expr\ArrowFunction ? 'arrow function' : 'closure');
                $this->add($node, 'PHP-COMPLEXITY', 'Function complexity requires review', "$name; cyclomatic complexity {$scope['complexity']}; maximum nesting {$scope['maxDepth']}", 'quality');
            }
        }
        return null;
    }
    private static function nested(Node $n): bool
    {
        return $n instanceof Node\Stmt\If_ || $n instanceof Node\Stmt\For_ || $n instanceof Node\Stmt\Foreach_ || $n instanceof Node\Stmt\While_ || $n instanceof Node\Stmt\Do_ || $n instanceof Node\Stmt\Switch_ || $n instanceof Node\Stmt\TryCatch || $n instanceof Node\Expr\Match_;
    }
    private static function decision(Node $n): bool
    {
        return $n instanceof Node\Stmt\If_ || $n instanceof Node\Stmt\ElseIf_ || $n instanceof Node\Stmt\For_ || $n instanceof Node\Stmt\Foreach_ || $n instanceof Node\Stmt\While_ || $n instanceof Node\Stmt\Do_ || $n instanceof Node\Stmt\Catch_ || $n instanceof Node\Stmt\Case_ && $n->cond !== null || $n instanceof Node\MatchArm && $n->conds !== null || $n instanceof Node\Expr\Ternary || $n instanceof Node\Expr\BinaryOp\BooleanAnd || $n instanceof Node\Expr\BinaryOp\BooleanOr || $n instanceof Node\Expr\BinaryOp\LogicalAnd || $n instanceof Node\Expr\BinaryOp\LogicalOr || $n instanceof Node\Expr\BinaryOp\LogicalXor || $n instanceof Node\Expr\BinaryOp\Coalesce;
    }
    private function add(Node $n, string $rule, string $summary, string $evidence, string $category = 'security'): void
    {
        $this->findings[] = ['category'=>$category,'ruleId'=>$rule,'subject'=>$this->file,'status'=>'review','summary'=>$summary,'evidence'=>$evidence,'recommendation'=>$category === 'quality' ? 'Consider simplifying the function and adding focused tests.' : 'Review the call and trace untrusted input before deciding whether it is exploitable.','file'=>$this->file,'line'=>$n->getStartLine()];
    }
}
