<?php
declare(strict_types=1);
$zip = new ZipArchive();
if ($zip->open($argv[1] ?? '') !== true) { fwrite(STDERR,"Cannot open package archive\n"); exit(1); }
$required = ['composer.json','bin/seculens','src/Assessment.php','README.md','README.jp.md','LICENSE','NOTICE','assets/OFL.txt','assets/NotoSansJP-Regular.otf'];
foreach ($required as $name) { if ($zip->locateName($name) === false) { fwrite(STDERR,"Missing package file: $name\n"); exit(1); } }
for ($i = 0; $i < $zip->numFiles; $i++) {
    $name = $zip->getNameIndex($i);
    if (preg_match('~^(?:vendor|tests|reports|releases|\.github|\.git|\.phpunit\.cache)/~',$name)) { fwrite(STDERR,"Unexpected package file: $name\n"); exit(1); }
}
echo "Package archive validated: {$zip->numFiles} files\n";
$zip->close();
