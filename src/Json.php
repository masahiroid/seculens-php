<?php
declare(strict_types=1);
namespace SecuLens;

final class Json
{
    public static function decode(string $text): mixed
    {
        return json_decode($text, true, 128, JSON_THROW_ON_ERROR);
    }
    public static function encode(mixed $value, bool $pretty = false): string
    {
        return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | ($pretty ? JSON_PRETTY_PRINT : 0));
    }
    public static function read(string $path): string
    {
        self::localPath($path);
        if (!is_file($path)) { throw new \InvalidArgumentException('Input must be a local regular file'); }
        $text = @file_get_contents($path);
        if ($text === false) {
            throw new \RuntimeException("Cannot read file: $path");
        }
        return $text;
    }
    public static function write(string $path, string $text): void
    {
        self::localPath($path);
        if (!is_dir(dirname($path))) { throw new \RuntimeException('Output directory does not exist'); }
        $temporary = tempnam(dirname($path), '.seculens-');
        if ($temporary === false) { throw new \RuntimeException('Cannot create output file'); }
        try {
            if (file_put_contents($temporary, $text) === false || !rename($temporary, $path)) {
                throw new \RuntimeException("Cannot write file: $path");
            }
        } finally { if (is_file($temporary)) { unlink($temporary); } }
    }
    public static function localPath(string $path): void
    {
        if ($path === '' || str_contains($path, "\0") || preg_match('~^[a-z][a-z0-9+.-]*://~i', $path)) {
            throw new \InvalidArgumentException("Only local filesystem paths are supported");
        }
    }
    public static function object(mixed $value, string $message): array
    {
        if (!is_array($value) || ($value !== [] && array_is_list($value))) {
            throw new \InvalidArgumentException($message);
        }
        return $value;
    }
    public static function list(mixed $value, string $message): array
    {
        if (!is_array($value) || !array_is_list($value)) {
            throw new \InvalidArgumentException($message);
        }
        return $value;
    }
    public static function text(mixed $value): bool
    {
        return is_string($value) && $value !== '';
    }
}
