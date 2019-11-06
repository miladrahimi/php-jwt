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
     * Get algorithm name
     *
     * @return string
     */
    public function getName(): string;

    /**
     * Sign the message
     *
     * @param string $message
     * @return string
     * @throws SigningException
     */
    public function sign(string $message): string;
}
