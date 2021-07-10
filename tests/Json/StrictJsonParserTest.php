<?php

namespace MiladRahimi\Jwt\Tests\Json;

use MiladRahimi\Jwt\Exceptions\JsonDecodingException;
use MiladRahimi\Jwt\Exceptions\JsonEncodingException;
use MiladRahimi\Jwt\Json\StrictJsonParser;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class StrictJsonParserTest extends TestCase
{
    /**
     * @throws Throwable
     */
    public function test_encode_and_decode_with_sample_data()
    {
        $data = [
            'string' => md5(mt_rand(1, 100)),
            'integer' => mt_rand(1, 100),
            'true' => true,
            'false' => false,
        ];

        $strictJson = new StrictJsonParser();
        $encoded = $strictJson->encode($data);
        $decoded = $strictJson->decode($encoded);

        $this->assertSame($data['string'], $decoded['string']);
        $this->assertSame($data['integer'], $decoded['integer']);
        $this->assertSame($data['true'], $decoded['true']);
        $this->assertSame($data['false'], $decoded['false']);
    }

    /**
     * @throws Throwable
     */
    public function test_encode_with_invalid_input_it_should_fail()
    {
        $strictJson = new StrictJsonParser();

        $this->expectException(JsonEncodingException::class);
        $strictJson->encode([NAN]);
    }

    /**
     * @throws Throwable
     */
    public function test_decode_with_invalid_json_it_should_fail()
    {
        $strictJson = new StrictJsonParser();

        $this->expectException(JsonDecodingException::class);
        $strictJson->decode('Invalid JSON');
    }

    /**
     * @throws Throwable
     */
    public function test_decode_with_non_standard_json_it_should_fail()
    {
        $strictJson = new StrictJsonParser();

        $this->expectException(JsonDecodingException::class);
        $strictJson->decode(json_encode('String!'));
    }
}
