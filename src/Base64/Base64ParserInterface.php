<?php

namespace MiladRahimi\Jwt\Base64;

/**
 * Interface Base64ParserInterface
 *
 * @package MiladRahimi\Jwt\Base64
 */
interface Base64ParserInterface
{
    /**
     * Encode plain text to Base64-encoded text
     *
     * @param string $data
     * @return string
     */
    public function encode(string $data): string;

    /**
     * Decode Base64-encoded text to plain text
     *
     * @param string $data
     * @return string
     */
    public function decode(string $data): string;
}
