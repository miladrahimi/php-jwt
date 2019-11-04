<?php

use MiladRahimi\Jwt\Cryptography\Keys\PrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\PublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use MiladRahimi\Jwt\Tests\TestCase;

class PairKeyTest extends TestCase
{
    public function test_public_key_with_wrong_file_path()
    {
        $this->expectException(InvalidKeyException::class);
        new PublicKey("/wrong");
    }

    public function test_private_key_with_wrong_file_path()
    {
        $this->expectException(InvalidKeyException::class);
        new PrivateKey("/wrong");
    }
}
