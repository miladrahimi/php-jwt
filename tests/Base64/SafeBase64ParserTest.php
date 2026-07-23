<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Tests\Base64;

use MiladRahimi\Jwt\Base64\SafeBase64Parser;
use MiladRahimi\Jwt\Exceptions\InvalidTokenException;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class SafeBase64ParserTest extends TestCase
{
    /**
     * @throws Throwable
     */
    public function test_encode_and_decode()
    {
        $plain = md5((string) random_int(1, 100));

        $safeBase64Parser = new SafeBase64Parser();
        $encoded = $safeBase64Parser->encode($plain);
        $decoded = $safeBase64Parser->decode($encoded);

        $this->assertEquals($plain, $decoded);
    }

    /**
     * Input outside the base64 alphabet must be rejected, not silently
     * stripped (strict decoding).
     *
     * @throws Throwable
     */
    public function test_decode_with_invalid_characters_it_should_fail()
    {
        $safeBase64Parser = new SafeBase64Parser();

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('The Base64 encoding is not valid.');
        $safeBase64Parser->decode('!!!!');
    }

    /**
     * @throws Throwable
     */
    public function test_decode_with_invalid_length_it_should_fail()
    {
        $safeBase64Parser = new SafeBase64Parser();

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('The Base64 encoding is not valid.');
        $safeBase64Parser->decode('a');
    }
}
