<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\Ecdsa;

use MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa\ES256Signer;
use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPrivateKey;
use MiladRahimi\Jwt\Exceptions\SigningException;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class AbstractEcdsaSignerTest extends TestCase
{
    protected EcdsaPrivateKey $privateKey;

    public function setUp(): void
    {
        parent::setUp();

        $this->privateKey = new EcdsaPrivateKey(__DIR__ . '/../../../../assets/keys/ecdsa256-private.pem');
    }

    /**
     * Builds a signer whose protected DER decoder is publicly reachable.
     */
    private function signer(): ES256Signer
    {
        return new class ($this->privateKey) extends ES256Signer {
            public function decodeDerPublicly(string $der, int $offset = 0): array
            {
                return $this->decodeDer($der, $offset);
            }

            public function derToSignaturePublicly(string $der, int $keySize): string
            {
                return $this->derToSignature($der, $keySize);
            }
        };
    }

    /**
     * When OpenSSL cannot sign (here: an unsupported digest algorithm), the signer must throw a SigningException.
     *
     * @throws Throwable
     */
    public function test_sign_with_an_unsupported_algorithm_it_should_fail()
    {
        $signer = new class ($this->privateKey) extends ES256Signer {
            protected function algorithm(): int
            {
                return PHP_INT_MAX;
            }
        };

        // The digest check fails inside PHP before OpenSSL is reached, so the error queue stays empty and the
        // fallback message is used. Drain stale entries so the queue state is deterministic.
        while (openssl_error_string() !== false) {
            continue;
        }

        // Swallow the PHP warning OpenSSL raises alongside returning false.
        set_error_handler(function (): bool {
            return true;
        }, E_WARNING);

        try {
            $this->expectException(SigningException::class);
            $this->expectExceptionMessage('OpenSSL cannot sign the token.');
            $signer->sign('Text');
        } finally {
            restore_error_handler();
        }
    }

    /**
     * The ASN.1 sign padding is stripped and each coordinate is left-padded to the fixed coordinate size,
     * regardless of the (random) integer values OpenSSL produces.
     *
     * @throws Throwable
     */
    public function test_der_to_signature_pads_each_coordinate_to_the_fixed_size()
    {
        $der = "\x30\x08\x02\x02\x00\x80\x02\x02\x00\x81";

        $signature = $this->signer()->derToSignaturePublicly($der, 256);

        $this->assertSame(str_repeat("\x00", 31) . "\x80" . str_repeat("\x00", 31) . "\x81", $signature);
    }

    /**
     * A full-size coordinate with a sign byte (33-byte INTEGER) is trimmed back to the coordinate size instead
     * of producing an oversized signature.
     *
     * @throws Throwable
     */
    public function test_der_to_signature_strips_the_sign_byte_of_full_size_coordinates()
    {
        $r = "\x00\x80" . str_repeat("\x01", 31);
        $s = "\x00\x81" . str_repeat("\x02", 31);
        $der = "\x30\x46\x02\x21" . $r . "\x02\x21" . $s;

        $signature = $this->signer()->derToSignaturePublicly($der, 256);

        $this->assertSame("\x80" . str_repeat("\x01", 31) . "\x81" . str_repeat("\x02", 31), $signature);
    }

    /**
     * A long-form DER length (0x81 prefix) is read from the following bytes.
     *
     * @throws Throwable
     */
    public function test_decode_der_with_a_long_form_length_it_should_read_the_value()
    {
        [$offset, $value] = $this->signer()->decodeDerPublicly("\x02\x81\x02\xAB\xCD");

        $this->assertSame(5, $offset);
        $this->assertSame("\xAB\xCD", $value);
    }

    /**
     * A BIT STRING element skips its leading "unused bits" byte.
     *
     * @throws Throwable
     */
    public function test_decode_der_with_a_bit_string_it_should_skip_the_unused_bits_byte()
    {
        [$offset, $value] = $this->signer()->decodeDerPublicly("\x03\x03\x00\xAB\xCD");

        $this->assertSame(5, $offset);
        $this->assertSame("\xAB\xCD", $value);
    }

    /**
     * A BIT STRING value excludes both the "unused bits" byte and any trailing data.
     *
     * @throws Throwable
     */
    public function test_decode_der_with_a_bit_string_it_should_not_read_past_its_length()
    {
        [$offset, $value] = $this->signer()->decodeDerPublicly("\x03\x03\x00\xAB\xCD\xEE");

        $this->assertSame(5, $offset);
        $this->assertSame("\xAB\xCD", $value);
    }

    /**
     * A multi-byte long-form length (0x82 prefix) is accumulated across all of its length bytes.
     *
     * @throws Throwable
     */
    public function test_decode_der_with_a_two_byte_long_form_length_it_should_read_the_value()
    {
        $value = str_repeat("\xAA", 256);

        [$offset, $decoded] = $this->signer()->decodeDerPublicly("\x02\x82\x01\x00" . $value);

        $this->assertSame(260, $offset);
        $this->assertSame($value, $decoded);
    }

    /**
     * A truncated long-form length stops at the end of the input instead of reading past it.
     *
     * @throws Throwable
     */
    public function test_decode_der_with_a_truncated_long_form_length_it_should_stop_at_the_end()
    {
        [$offset, $value] = $this->signer()->decodeDerPublicly("\x02\x81");

        $this->assertSame(2, $offset);
        $this->assertSame('', $value);
    }

    /**
     * A constructed element (bit 5 of the tag byte, here a constructed OCTET STRING) yields no value; the offset
     * lands on its first child so the caller can descend into it.
     *
     * @throws Throwable
     */
    public function test_decode_der_with_a_constructed_element_it_should_descend_into_it()
    {
        [$offset, $value] = $this->signer()->decodeDerPublicly("\x24\x02\xAB\xCD");

        $this->assertSame(2, $offset);
        $this->assertSame('', $value);
    }
}
