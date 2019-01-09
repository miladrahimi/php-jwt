<?php
/**
 * Created by PhpStorm.
 * User: Milad Rahimi <info@miladrahimi.com>
 * Date: 5/14/2018 AD
 * Time: 00:37
 */

namespace MiladRahimi\Jwt\Json;

use MiladRahimi\Jwt\Exceptions\JsonDecodingException;

interface JsonParserInterface
{
    /**
     * Encode JSON
     *
     * @param array $data
     * @return string
     */
    public function encode(array $data): string;

    /**
     * Decode JSON
     *
     * @param string $data
     * @return array
     * @throws JsonDecodingException
     */
    public function decode(string $data): array;
}