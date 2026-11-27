<?php
declare(strict_types=1);
namespace SecuLens;

/** Waivers: recorded, expiring customer decisions. Waived findings stay in the report. */
final class Waivers
{
    public const LIMITATION = 'Waivers record customer-approved decisions that SecuLens does not verify; waived findings remain in the report and are excluded only from exit codes.';
    private const KEYS = ['ruleId','subject','justification','approvedBy','expires'];

    public static function isCalendarDate(mixed $value): bool
    {
        if (!is_string($value) || !preg_match('/^(\d{4})-(\d{2})-(\d{2})$/D', $value, $m)) { return false; }
        return checkdate((int)$m[2], (int)$m[3], (int)$m[1]);
    }
    private static function text(mixed $value): bool { return is_string($value) && trim($value) !== ''; }
    private static function isObject(mixed $value): bool { return $value instanceof \stdClass || (is_array($value) && $value !== [] && !array_is_list($value)); }
    private static function fields(mixed $value): array { return $value instanceof \stdClass ? get_object_vars($value) : $value; }

    /**
     * Validates a decoded waiver file and returns it as associative arrays. Decode with objects
     * (json_decode($text, false)) so that {} and [] stay distinct; arrays are also accepted.
     */
    public static function validate(mixed $input): array
    {
        if (!self::isObject($input)) { throw new \InvalidArgumentException('Waiver file must be an object'); }
        $data = self::fields($input);
        foreach (array_keys($data) as $key) { if (!in_array($key, ['schemaVersion','waivers'], true)) { throw new \InvalidArgumentException("Waiver file has unknown key $key"); } }
        if (($data['schemaVersion'] ?? null) !== '1.0') { throw new \InvalidArgumentException('Waiver file schemaVersion must be 1.0'); }
        if (!is_array($data['waivers'] ?? null) || !array_is_list($data['waivers'])) { throw new \InvalidArgumentException('Waiver file waivers must be an array'); }
        foreach ($data['waivers'] as $index => $entry) {
            $path = "waivers[$index]";
            if (!self::isObject($entry)) { throw new \InvalidArgumentException("Waiver $path must be an object"); }
            $entry = self::fields($entry);
            foreach (array_keys($entry) as $key) { if (!in_array($key, self::KEYS, true)) { throw new \InvalidArgumentException("Waiver $path has unknown key $key"); } }
            foreach (['ruleId','justification','approvedBy'] as $key) { if (!self::text($entry[$key] ?? null)) { throw new \InvalidArgumentException("Waiver $path.$key is required"); } }
            if (array_key_exists('subject', $entry) && !self::text($entry['subject'])) { throw new \InvalidArgumentException("Waiver $path.subject must be a non-empty string"); }
            if (!self::isCalendarDate($entry['expires'] ?? null)) { throw new \InvalidArgumentException("Waiver $path.expires must be a YYYY-MM-DD date"); }
        }
        return json_decode(json_encode($input, JSON_THROW_ON_ERROR), true, 128, JSON_THROW_ON_ERROR);
    }
    private static function describe(array $w): string { return $w['ruleId'].(array_key_exists('subject', $w) ? ' on '.$w['subject'] : ''); }
    private static function matches(array $w, array $f): bool
    {
        return ($w['ruleId'] === $f['ruleId'] || in_array($w['ruleId'], $f['aliases'] ?? [], true)) && (!array_key_exists('subject', $w) || $w['subject'] === $f['subject']);
    }
    /**
     * Annotates findings covered by an active waiver (expires on or after $date, YYYY-MM-DD)
     * and appends a review finding for each waiver that expired or matched nothing.
     */
    public static function apply(array $findings, array $waivers, string $date): array
    {
        if (!self::isCalendarDate($date)) { throw new \InvalidArgumentException('Waiver date must be YYYY-MM-DD'); }
        $used = []; $expired = []; $result = [];
        foreach ($findings as $finding) {
            $active = null;
            foreach ($waivers as $i => $w) {
                if (!self::matches($w, $finding)) { continue; }
                $used[$i] = true;
                if (strcmp($w['expires'], $date) < 0) { $expired[$i] = true; } elseif ($active === null) { $active = $i; }
            }
            if ($active !== null) {
                $w = $waivers[$active];
                $finding['waiver'] = ['source'=>"waivers[$active]",'justification'=>$w['justification'],'approvedBy'=>$w['approvedBy'],'expires'=>$w['expires']];
            }
            $result[] = $finding;
        }
        foreach ($waivers as $i => $w) {
            if (isset($expired[$i])) {
                $result[] = ['category'=>'quality','ruleId'=>'WAIVER-EXPIRED','subject'=>"waivers[$i]",'status'=>'review','summary'=>'Waiver expired','evidence'=>self::describe($w)." expired {$w['expires']}; approved by {$w['approvedBy']}",'recommendation'=>'Remediate the finding or renew the waiver after a new review.'];
            } elseif (!isset($used[$i])) {
                $result[] = ['category'=>'quality','ruleId'=>'WAIVER-UNMATCHED','subject'=>"waivers[$i]",'status'=>'review','summary'=>'Waiver matched no finding','evidence'=>self::describe($w)."; expires {$w['expires']}",'recommendation'=>'Remove the waiver, or correct its ruleId or subject.'];
            }
        }
        return $result;
    }
    /** Findings that count toward exit codes: everything without an active waiver. */
    public static function unwaived(array $findings): array
    {
        return array_values(array_filter($findings, static fn(array $f): bool => !isset($f['waiver'])));
    }
}
