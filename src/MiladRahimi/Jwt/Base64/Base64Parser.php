<?php
/**
 * Created by PhpStorm.
 * User: Milad Rahimi <info@miladrahimi.com>
 * Date: 5/13/2018 AD
 * Time: 23:47
 */

namespace MiladRahimi\Jwt\Base64;

class Base64Parser implements Base64ParserInterface
{
    /**
     * Encode data by Base64 algorithm
     *
     * @param string $data
     * @return string
     */
    public function encode(string $data): string
    {
        return str_replace('=', '', strtr(base64_encode($data), '+/', '-_'));
    }

    /**
     * Decode Base64-encoded data to plain text
     *
     * @param string $data
     * @return string
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