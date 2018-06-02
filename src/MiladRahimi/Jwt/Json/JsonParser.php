<?php
/**
 * Created by PhpStorm.
 * User: Milad Rahimi <info@miladrahimi.com>
 * Date: 5/14/2018 AD
 * Time: 00:27
 */

namespace MiladRahimi\Jwt\Json;

use MiladRahimi\Jwt\Exceptions\InvalidJsonException;

class JsonParser implements JsonParserInterface
{
    /**
     * Encode JSON
     *
     * @param array $data
     * @return string
     */
    public function encode(array $data): string
    {
        return json_encode($data);
    }

    /**
     * Decode JSON
     *
     * @param string $data
     * @return array
     * @throws InvalidJsonException
     */
    public function decode(string $data): array
    {
        $result = json_decode($data, true);

        if (json_last_error()) {
            throw new InvalidJsonException(json_last_error_msg(), json_last_error());
        }

        if (is_array($result) == false) {
            throw new InvalidJsonException();
        }

        return $result;
    }
}