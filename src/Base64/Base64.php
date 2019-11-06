<?php

namespace MiladRahimi\Jwt\Base64;

/**
 * Interface Base64
 *
 * @package MiladRahimi\Jwt\Base64
 */
interface Base64
{
    /**
     * Encode plain data to Base64-encoded data
     *
     * @param string $data
     * @return string
     */
    public function encode(string $data): string;

    /**
     * Decode Base64-encoded data to plain data
     *
     * @param string $data
     * @return string
     */
    public function decode(string $data): string;
}
