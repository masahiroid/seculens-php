<?php
declare(strict_types=1);
namespace SecuLens;
use Symfony\Component\Process\Process;

final class Generator
{
    public static function generate(string $target, string $format, string $output, string $syft = 'syft'): void
    {
        Json::localPath($target); Json::localPath($output);
        if (!is_dir($target) || is_link($target)) { throw new \InvalidArgumentException('SBOM target must be an existing directory, not a symlink'); }
        if (!in_array($format, ['cyclonedx','spdx'], true)) { throw new \InvalidArgumentException('Format must be cyclonedx or spdx'); }
        $target = realpath($target);
        $process = new Process([$syft, 'dir:'.$target, '-o', $format === 'cyclonedx' ? 'cyclonedx-json' : 'spdx-json']);
        $process->setEnv(['SYFT_CHECK_FOR_APP_UPDATE'=>'false']);
        $process->setTimeout(300); $process->mustRun();
        $text = $process->getOutput(); Sbom::parse(Json::decode($text));
        $directory = dirname($output);
        if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) { throw new \RuntimeException('Cannot create SBOM output directory'); }
        Json::write($output, $text);
    }
}
