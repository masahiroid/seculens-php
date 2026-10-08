<?php
declare(strict_types=1);
namespace SecuLens;

/** OOXML font obfuscation, retaining the bundled SIL OFL font. */
final class FontEmbedder
{
    public static function embed(string $path): void
    {
        $zip = new \ZipArchive();
        if ($zip->open($path) !== true) { throw new \RuntimeException('Cannot open Word report for font embedding'); }
        try {
            $bytes = random_bytes(16);
            $hex = strtoupper(bin2hex($bytes));
            $guid = substr($hex,0,8).'-'.substr($hex,8,4).'-'.substr($hex,12,4).'-'.substr($hex,16,4).'-'.substr($hex,20);
            $key = strrev($bytes);
            $font = Json::read(dirname(__DIR__).'/assets/NotoSansJP-Regular.otf');
            for ($i = 0; $i < 32; $i++) { $font[$i] = chr(ord($font[$i]) ^ ord($key[$i % 16])); }
            self::add($zip, 'word/fonts/NotoSansJP.odttf', $font);
            $ns = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main';
            $rns = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';
            $xml = self::xml($zip, 'word/fontTable.xml');
            $xpath = new \DOMXPath($xml); $xpath->registerNamespace('w', $ns);
            $entry = $xpath->query('//w:font[@w:name="Noto Sans JP"]')->item(0);
            if ($entry === null) { $entry = $xml->createElementNS($ns, 'w:font'); $entry->setAttributeNS($ns, 'w:name', 'Noto Sans JP'); $xml->documentElement->appendChild($entry); }
            $embedded = $xml->createElementNS($ns, 'w:embedRegular');
            $embedded->setAttributeNS($rns, 'r:id', 'rIdSecuLensFont'); $embedded->setAttributeNS($ns, 'w:fontKey', '{'.$guid.'}'); $embedded->setAttributeNS($ns, 'w:subsetted', 'false'); $entry->appendChild($embedded);
            self::add($zip, 'word/fontTable.xml', $xml->saveXML());
            $relsName = 'word/_rels/fontTable.xml.rels';
            $rels = new \DOMDocument('1.0','UTF-8');
            $relNs = 'http://schemas.openxmlformats.org/package/2006/relationships';
            if ($zip->locateName($relsName) !== false) { $rels = self::xml($zip, $relsName); }
            else { $rels->appendChild($rels->createElementNS($relNs, 'Relationships')); }
            $rel = $rels->createElementNS($relNs, 'Relationship');
            $rel->setAttribute('Id', 'rIdSecuLensFont'); $rel->setAttribute('Type', $rns.'/font'); $rel->setAttribute('Target', 'fonts/NotoSansJP.odttf'); $rels->documentElement->appendChild($rel); self::add($zip, $relsName, $rels->saveXML());
            $types = self::xml($zip, '[Content_Types].xml');
            $default = $types->createElementNS('http://schemas.openxmlformats.org/package/2006/content-types', 'Default');
            $default->setAttribute('Extension', 'odttf'); $default->setAttribute('ContentType', 'application/vnd.openxmlformats-officedocument.obfuscatedFont'); $types->documentElement->appendChild($default); self::add($zip, '[Content_Types].xml', $types->saveXML());
            $settings = self::xml($zip, 'word/settings.xml'); $settings->documentElement->appendChild($settings->createElementNS($ns, 'w:embedTrueTypeFonts')); self::add($zip, 'word/settings.xml', $settings->saveXML());
        } finally { if (!$zip->close()) { throw new \RuntimeException('Cannot save embedded Word font'); } }
    }
    private static function xml(\ZipArchive $zip, string $name): \DOMDocument
    {
        $data = $zip->getFromName($name); $xml = new \DOMDocument();
        if ($data === false || !$xml->loadXML($data, LIBXML_NONET)) { throw new \RuntimeException("Invalid Word XML: $name"); }
        return $xml;
    }
    private static function add(\ZipArchive $zip, string $name, string $text): void
    {
        if (!$zip->addFromString($name, $text)) { throw new \RuntimeException("Cannot add Word part: $name"); }
    }
}
