<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Keys;

class HmacKey
{
    protected string $content;

    protected ?string $id;

    /**
     * @param string $key Key in string format
     * @param string|null $id Key identifier
     */
    public function __construct(string $key, ?string $id = null)
    {
        $this->content = $key;
        $this->id = $id;
    }

    public function getContent(): string
    {
        return $this->content;
    }

    public function getId(): ?string
    {
        return $this->id;
    }
}
