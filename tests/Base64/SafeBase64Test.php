<?php

namespace MiladRahimi\Jwt\Tests\Base64;

use MiladRahimi\Jwt\Base64\SafeBase64;
use MiladRahimi\Jwt\Tests\TestCase;

class SafeBase64Test extends TestCase
{
    public function test_encode_and_decode_methods()
    {
        $plain = md5(mt_rand(1, 100));

        $safeBase64 = new SafeBase64();
        $encoded = $safeBase64->encode($plain);
        $decoded = $safeBase64->decode($encoded);

        $this->assertEquals($plain, $decoded);
    }
}
