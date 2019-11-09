<?php

namespace MiladRahimi\Jwt\Cryptography;

use MiladRahimi\Jwt\Exceptions\SigningException;

/**
 * Interface Signer
 *
 * @package MiladRahimi\Jwt\Cryptography
 */
interface Signer
{
    /**
     * Algorithm name
     *
     * @return string
     */
    public function name(): string;

    /**
     * Sign the message
     *
     * @param string $message
     * @return string
     * @throws SigningException
     */
    public function sign(string $message): string;
}
