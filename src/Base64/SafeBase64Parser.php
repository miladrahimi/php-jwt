<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Base64;

use MiladRahimi\Jwt\Exceptions\InvalidTokenException;

class SafeBase64Parser implements Base64Parser
{
    /**
     * {@inheritDoc}
     */
    public function encode(string $data): string
    {
        return str_replace('=', '', strtr(base64_encode($data), '+/', '-_'));
    }

    /**
     * {@inheritDoc}
     */
    public function decode(string $data): string
    {
        if ($remainder = strlen($data) % 4) {
            $paddingLength = 4 - $remainder;
            $data .= str_repeat('=', $paddingLength);
        }

        $decoded = base64_decode(strtr($data, '-_', '+/'), true);
        if ($decoded === false) {
            throw new InvalidTokenException('The Base64 encoding is not valid.');
        }

        return $decoded;
    }
}
