<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Keys;

use MiladRahimi\Jwt\Exceptions\InvalidKeyException;

class EdDsaPrivateKey
{
    /**
     * @var non-empty-string
     */
    protected string $content;

    protected ?string $id;

    /**
     * @param string $key Key in string format
     * @param string|null $id Key identifier
     *
     * @throws InvalidKeyException
     */
    public function __construct(string $key, ?string $id = null)
    {
        if ($key === '') {
            throw new InvalidKeyException('The key must not be empty.');
        }

        $this->content = $key;
        $this->id = $id;
    }

    /**
     * @return non-empty-string
     */
    public function getContent(): string
    {
        return $this->content;
    }

    public function getId(): ?string
    {
        return $this->id;
    }
}
