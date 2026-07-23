<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Base64;

use MiladRahimi\Jwt\Exceptions\InvalidTokenException;

interface Base64Parser
{
    /**
     * Encodes the plain data to a Base64URL string.
     */
    public function encode(string $data): string;

    /**
     * Decodes the Base64URL string to plain data.
     *
     * @throws InvalidTokenException When the encoding is not valid.
     */
    public function decode(string $data): string;
}
