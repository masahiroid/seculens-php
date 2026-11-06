<?php
declare(strict_types=1);
namespace SecuLens;

use Opis\JsonSchema\CompliantValidator;
use Opis\JsonSchema\Errors\ErrorFormatter;

final class Validation
{
    /** Pass JSON objects as stdClass, preserving the distinction between {} and []. */
    public static function validate(mixed $data, string $kind = 'sbom'): array
    {
        if ($kind === 'report') { $name = $data instanceof \stdClass && ($data->schemaVersion ?? null) === '1.1' ? 'report-1.1.schema.json' : 'report-1.2.schema.json'; }
        elseif ($kind !== 'sbom') { throw new \InvalidArgumentException('Kind must be sbom or report'); }
        elseif ($data instanceof \stdClass && ($data->bomFormat ?? null) === 'CycloneDX' && in_array($data->specVersion ?? null, ['1.4','1.5','1.6','1.7'], true)) {
            $name = 'bom-'.$data->specVersion.'.schema.json';
        } elseif ($data instanceof \stdClass && in_array($data->spdxVersion ?? null, ['SPDX-2.2','SPDX-2.3'], true)) {
            $name = 'spdx-'.substr($data->spdxVersion,5).'.schema.json';
        } else { return ['valid'=>false,'schema'=>'','errors'=>[['path'=>'','message'=>'Expected supported SPDX or CycloneDX version']]]; }
        $validator = new CompliantValidator();
        $directory = dirname(__DIR__).'/schemas/';
        foreach (['spdx.schema.json','jsf-0.82.schema.json','cryptography-defs.schema.json'] as $file) {
            $validator->resolver()->registerRaw(json_decode(Json::read($directory.$file), false, 128, JSON_THROW_ON_ERROR));
        }
        $schema = json_decode(Json::read($directory.$name), false, 128, JSON_THROW_ON_ERROR);
        $result = $validator->validate($data, $schema);
        $errors = [];
        if (!$result->isValid()) {
            foreach ((new ErrorFormatter())->format($result->error()) as $path => $messages) {
                foreach ($messages as $message) { $errors[] = ['path'=>$path === '/' ? '' : $path,'message'=>$message]; }
            }
        }
        return ['valid'=>$result->isValid(),'schema'=>$name,'errors'=>$errors];
    }
}
