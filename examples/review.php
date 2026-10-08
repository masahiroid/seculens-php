<?php
// Demonstration input only. SecuLens parses this file without executing it.
function evaluateInput(string $expression): mixed
{
    return eval($expression);
}
function runCommand(string $command): string|false|null
{
    return shell_exec($command);
}
function decodeObject(string $serialized): mixed
{
    return unserialize($serialized);
}
function loadPage(string $path): void
{
    include $path;
}
function passwordDigest(string $password): string
{
    return md5($password);
}
function queryRecords($connection, string $name): mixed
{
    return $connection->query("SELECT * FROM users WHERE name = '" . $name . "'");
}
