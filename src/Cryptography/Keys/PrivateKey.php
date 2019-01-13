<?php

namespace MiladRahimi\Jwt\Cryptography\Keys;

use MiladRahimi\Jwt\Exceptions\InvalidKeyException;

/**
 * Class PrivateKey
 *
 * @package MiladRahimi\Jwt\Cryptography\Keys
 */
class PrivateKey
{
    /**
     * @var resource    Key file resource handler
     */
    private $resource;

    /**
     * PrivateKey constructor.
     *
     * @param string $fileFullPath
     * @throws InvalidKeyException
     */
    public function __construct(string $fileFullPath)
    {
        $this->resource = openssl_pkey_get_private('file:///' . $fileFullPath);

        if (empty($this->resource)) {
            throw new InvalidKeyException();
        }
    }

    /**
     * @return resource
     */
    public function getResource()
    {
        return $this->resource;
    }
}
