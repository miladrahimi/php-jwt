<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Base64;

interface Base64Parser
{
    /**
     * Encodes the plain data to a Base64URL string.
     */
    public function encode(string $data): string;

    /**
     * Decodes the Base64URL string to plain data.
     */
    public function decode(string $data): string;
}
