<?php

namespace MiladRahimi\Jwt\Json;

use MiladRahimi\Jwt\Exceptions\JsonDecodingException;
use MiladRahimi\Jwt\Exceptions\JsonEncodingException;

/**
 * Interface JsonParserInterface
 *
 * @package MiladRahimi\Jwt\Json
 */
interface JsonParserInterface
{
    /**
     * Encode array to JSON
     *
     * @param array $data
     * @return string
     * @throws JsonEncodingException
     */
    public function encode(array $data): string;

    /**
     * Decode JSON to array
     *
     * @param string $json
     * @return array
     * @throws JsonDecodingException
     */
    public function decode(string $json): array;
}
