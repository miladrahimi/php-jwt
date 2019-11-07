<?php

namespace MiladRahimi\Jwt\Json;

use MiladRahimi\Jwt\Exceptions\JsonDecodingException;
use MiladRahimi\Jwt\Exceptions\JsonEncodingException;

/**
 * Class StrictJson
 *
 * @package MiladRahimi\Jwt\Json
 */
class StrictJsonParser implements JsonParser
{
    /**
     * @inheritdoc
     */
    public function encode(array $data): string
    {
        $json = json_encode($data);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new JsonEncodingException(json_last_error_msg(), json_last_error());
        }

        return $json;
    }

    /**
     * @inheritdoc
     */
    public function decode(string $json): array
    {
        $result = json_decode($json, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new JsonDecodingException(json_last_error_msg(), json_last_error());
        }

        // It must be a standard JSON
        if (is_array($result) == false) {
            throw new JsonDecodingException();
        }

        return $result;
    }
}
