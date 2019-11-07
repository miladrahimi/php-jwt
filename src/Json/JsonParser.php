<?php

namespace MiladRahimi\Jwt\Json;

use MiladRahimi\Jwt\Exceptions\JsonDecodingException;
use MiladRahimi\Jwt\Exceptions\JsonEncodingException;

/**
 * Interface JsonParser
 *
 * @package MiladRahimi\Jwt\Json
 */
interface JsonParser
{
    /**
     * Encode array data to JSON
     *
     * @param array $data
     * @return string
     * @throws JsonEncodingException
     */
    public function encode(array $data): string;

    /**
     * Decode JSON to array data
     *
     * @param string $json
     * @return array
     * @throws JsonDecodingException
     */
    public function decode(string $json): array;
}
