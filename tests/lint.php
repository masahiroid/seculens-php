<?php
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
$root = dirname(__DIR__); $failed = false;
foreach (['src','tests','bin'] as $directory) {
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root.'/'.$directory, FilesystemIterator::SKIP_DOTS)) as $file) {
        if ($file->getExtension() !== 'php' && $file->getBasename() !== 'seculens') { continue; }
        $process = new Symfony\Component\Process\Process([PHP_BINARY, '-l', $file->getPathname()]);
        $process->run();
        if (!$process->isSuccessful()) { fwrite(STDERR, $process->getOutput().$process->getErrorOutput()); $failed = true; }
    }
}
exit($failed ? 1 : 0);
