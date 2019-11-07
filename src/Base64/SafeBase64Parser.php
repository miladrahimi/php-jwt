<?php

namespace MiladRahimi\Jwt\Base64;

/**
 * Class SafeBase64
 *
 * @package MiladRahimi\Jwt\Base64
 */
class SafeBase64Parser implements Base64Parser
{
    /**
     * @inheritdoc
     */
    public function encode(string $data): string
    {
        return str_replace('=', '', strtr(base64_encode($data), '+/', '-_'));
    }

    /**
     * @inheritdoc
     */
    public function decode(string $data): string
    {
        if ($remainder = strlen($data) % 4) {
            $paddingLength = 4 - $remainder;
            $data .= str_repeat('=', $paddingLength);
        }

        return base64_decode(strtr($data, '-_', '+/'));
    }
}
