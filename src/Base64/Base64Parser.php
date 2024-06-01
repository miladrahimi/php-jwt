<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Base64;

interface Base64Parser
{
    /**
     * Encode plain data to Base64-encoded data
     */
    public function encode(string $data): string;

    /**
     * Decode Base64-encoded data to plain data
     */
    public function decode(string $data): string;
}
