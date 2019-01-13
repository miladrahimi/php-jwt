<?php

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Base64\Base64Parser;
use MiladRahimi\Jwt\Base64\Base64ParserInterface;

class Base64ParserTest extends TestCase
{
    /**
     * @var Base64ParserInterface
     */
    private $service;

    public function setUp()
    {
        parent::setUp();

        $this->service = new Base64Parser();
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
