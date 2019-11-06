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
     * Sign plain text
     *
     * @param string $data
     * @return string
     * @throws SigningException
     */
    public function sign(string $data): string;
}
