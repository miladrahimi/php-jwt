<?php
/**
 * Created by PhpStorm.
 * User: Milad Rahimi <info@miladrahimi.com>
 * Date: 5/14/2018 AD
 * Time: 00:27
 */

namespace MiladRahimi\Jwt\Json;

use MiladRahimi\Jwt\Exceptions\JsonDecodingException;

class JsonParser implements JsonParserInterface
{
    /**
     * Encode JSON
     *
     * @param array $data
     * @return string
     * @throws JsonDecodingException
     */
    public function encode(array $data): string
    {
        $json = json_encode($data);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new JsonDecodingException(json_last_error_msg(), json_last_error());
        }

        return $json;
    }

    /**
     * Decode JSON
     *
     * @param string $data
     * @return array
     * @throws JsonDecodingException
     */
    public function decode(string $data): array
    {
        $result = json_decode($data, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new JsonDecodingException(json_last_error_msg(), json_last_error());
        }

        return $result;
    }
}