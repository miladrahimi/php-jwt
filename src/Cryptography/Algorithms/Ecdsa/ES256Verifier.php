<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa;

class ES256Verifier extends AbstractEcdsaVerifier
{
    protected static string $name = 'ES256';
}
