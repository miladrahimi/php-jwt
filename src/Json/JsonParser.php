<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Json;

use MiladRahimi\Jwt\Exceptions\JsonDecodingException;
use MiladRahimi\Jwt\Exceptions\JsonEncodingException;

interface JsonParser
{
    /**
     * Encodes the array data to a JSON string.
     *
     * @param array<string, mixed> $data
     * @throws JsonEncodingException
     */
    public function encode(array $data): string;

    /**
     * Decodes the JSON string to array data.
     *
     * @return array<string, mixed>
     * @throws JsonDecodingException
     */
    public function decode(string $json): array;
}
