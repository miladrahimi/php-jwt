<?php

namespace MiladRahimi\Jwt\Tests\Base64;

use MiladRahimi\Jwt\Base64\SafeBase64Parser;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class SafeBase64ParserTest extends TestCase
{
    /**
     * @throws Throwable
     */
    public function test_encode_and_decode()
    {
        $plain = md5(random_int(1, 100));

        $safeBase64Parser = new SafeBase64Parser();
        $encoded = $safeBase64Parser->encode($plain);
        $decoded = $safeBase64Parser->decode($encoded);

        $this->assertEquals($plain, $decoded);
    }
}
