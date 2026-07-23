<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Json;

use MiladRahimi\Jwt\Exceptions\JsonDecodingException;
use MiladRahimi\Jwt\Exceptions\JsonEncodingException;

class StrictJsonParser implements JsonParser
{
    /**
     * {@inheritDoc}
     */
    public function encode(array $data): string
    {
        $json = json_encode($data);

        if ($json === false) {
            throw new JsonEncodingException(json_last_error_msg(), json_last_error());
        }

        return $json;
    }

    /**
     * {@inheritDoc}
     */
    public function decode(string $json): array
    {
        $result = json_decode($json, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new JsonDecodingException(json_last_error_msg(), json_last_error());
        }

        if (!is_array($result)) {
            throw new JsonDecodingException('Claims are not in array format.');
        }

        return $result;
    }
}
