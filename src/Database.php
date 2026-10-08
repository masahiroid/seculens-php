<?php
declare(strict_types=1);
namespace SecuLens;

final class Database
{
    public static function validate(mixed $data): array
    {
        $records = is_array($data) && array_is_list($data) ? $data : ($data['records'] ?? null);
        $records = Json::list($records, 'Database must be an OSV array or {records: [...]}');
        $seen = [];
        foreach ($records as $r) {
            $r = Json::object($r, 'Invalid OSV record');
            if (!Json::text($r['id'] ?? null) || isset($seen[$r['id']])) { throw new \InvalidArgumentException('Missing or duplicate OSV ID'); }
            $seen[$r['id']] = true;
            foreach (Json::list($r['affected'] ?? null, 'Invalid affected array') as $a) {
                $a = Json::object($a, 'Invalid affected entry');
                if (!Json::text($a['package']['name'] ?? null) || !Json::text($a['package']['ecosystem'] ?? null)) { throw new \InvalidArgumentException('Invalid affected package'); }
                foreach (Json::list($a['versions'] ?? [], 'Invalid versions') as $v) { if (!is_string($v)) { throw new \InvalidArgumentException('Invalid version'); } }
                foreach (Json::list($a['ranges'] ?? [], 'Invalid ranges') as $range) {
                    if (!Json::text($range['type'] ?? null)) { throw new \InvalidArgumentException('Invalid range type'); }
                    foreach (Json::list($range['events'] ?? null, 'Invalid events') as $event) {
                        $event = Json::object($event, 'Invalid event');
                        if (count($event) !== 1 || !in_array(array_key_first($event), ['introduced','fixed','last_affected','limit'], true) || !Json::text(reset($event))) { throw new \InvalidArgumentException('Invalid OSV range event'); }
                    }
                }
            }
            foreach (Json::list($r['aliases'] ?? [], 'Invalid aliases') as $alias) { if (!Json::text($alias)) { throw new \InvalidArgumentException('Invalid alias'); } }
            foreach (Json::list($r['references'] ?? [], 'Invalid references') as $ref) { if (!Json::text($ref['url'] ?? null)) { throw new \InvalidArgumentException('Invalid reference'); } }
        }
        return $records;
    }
    /** Send names/ecosystems only; version matching stays local. */
    public static function fetch(array $components, ?callable $request = null): array
    {
        $request ??= self::post(...);
        $seen = []; $records = [];
        foreach ($components as $c) {
            if (!isset($c['ecosystem'])) { continue; }
            $key = $c['ecosystem'].'|'.$c['name'];
            if (isset($seen[$key])) { continue; }
            $seen[$key] = true; $token = null; $tokens = []; $pages = 0;
            do {
                if (++$pages > 1000) { throw new \RuntimeException('OSV pagination limit exceeded'); }
                $body = ['package' => ['name' => $c['name'], 'ecosystem' => $c['ecosystem']]];
                if ($token !== null) { $body['page_token'] = $token; }
                $data = Json::object($request($body), 'Invalid OSV response');
                foreach (self::validate($data['vulns'] ?? []) as $r) { $records[$r['id']] = $r; }
                $token = $data['next_page_token'] ?? null;
                if ($token === '') { $token = null; }
                if ($token !== null) {
                    if (!is_string($token) || isset($tokens[$token])) { throw new \RuntimeException('Invalid or repeated OSV pagination token'); }
                    $tokens[$token] = true;
                }
            } while ($token !== null);
        }
        ksort($records); return array_values($records);
    }
    private static function post(array $body): mixed
    {
        $ch = curl_init('https://api.osv.dev/v1/query');
        curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => Json::encode($body), CURLOPT_HTTPHEADER => ['Content-Type: application/json'], CURLOPT_RETURNTRANSFER => true, CURLOPT_CONNECTTIMEOUT => 10, CURLOPT_TIMEOUT => 30, CURLOPT_FOLLOWLOCATION => false, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS]);
        $text = curl_exec($ch); $status = curl_getinfo($ch, CURLINFO_HTTP_CODE); $error = curl_error($ch); curl_close($ch);
        if ($text === false || $status < 200 || $status >= 300) { throw new \RuntimeException("OSV request failed (HTTP $status): $error"); }
        return Json::decode($text);
    }
}
