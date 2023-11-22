<?php declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Keys;

class EdDsaPrivateKey
{
    private string $content;

    protected ?string $id;

    public function __construct(string $value, ?string $id = null)
    {
        $this->content = $value;
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
