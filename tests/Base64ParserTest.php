<?php

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Base64\SafeBase64;
use MiladRahimi\Jwt\Base64\Base64;

class Base64ParserTest extends TestCase
{
    /**
     * @var Base64
     */
    private $service;

    public function setUp()
    {
        parent::setUp();

        $this->service = new SafeBase64();
    }

    public function test_encoding_and_decoding_it_should_get_done_successfully()
    {
        $plainText = md5(mt_rand(1, 100));

        $encoded = $this->service->encode($plainText);

        $this->assertNotEmpty($encoded);

        $decoded = $this->service->decode($encoded);

        $this->assertEquals($plainText, $decoded);
    }
}
