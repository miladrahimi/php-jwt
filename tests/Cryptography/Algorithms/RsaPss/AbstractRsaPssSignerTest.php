<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\RsaPss;

use MiladRahimi\Jwt\Cryptography\Algorithms\RsaPss\PS256Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\RsaPss\PS256Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPublicKey;
use MiladRahimi\Jwt\Exceptions\SigningException;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class AbstractRsaPssSignerTest extends TestCase
{
    /**
     * The signature the encoder must produce for the message `Text` under the 2041-bit fixture key with the
     * salt fixed to `\xAB` * 32 — that modulus leaves no excess bits to clear and prepends a zero byte, so the
     * whole encode path is pinned byte for byte. The OpenSSL CLI verifies this vector (PSS with salt length 32).
     */
    private const FIXED_SALT_SIGNATURE_2041 =
        'ARZEDL31+Fo7wUwGXgh2nqc8J6I6Tbc5gRfzYIsVeJQhXW+1/nqoP9KDVDZy7O46jX52Fze7+c1wFBAuq3c1BOkBtcx0zZOf'
        . 'Jp6aZh6Vpvb5xhxcPb8+btLtGffC4Ypp2WcnGYdIuBYa0OGINAUNn5P9fMMxk3WJFYUDHzQx3I7NlaRISXmTSqrJOJUlardQ'
        . 'P5Agmo/DKbXJmSmCyGm+lgeFAG+Rn2XvFGHhLc8nOrMA2uA5GFxWzAb2cMbosN95SwlqSinL0iEJG7BBFtGjUNjDxuMdd2j9'
        . 'nN+sU3fzm1aIRI7tuqOtUkzoXJodg6APJn5zSbCnOIZ/8OTJ3YDfTA==';

    protected RsaPrivateKey $rsaPrivateKey;

    protected RsaPublicKey $rsaPublicKey;

    public function setUp(): void
    {
        parent::setUp();

        $this->rsaPrivateKey = new RsaPrivateKey(__DIR__ . '/../../../../assets/keys/rsa-private.pem');
        $this->rsaPublicKey = new RsaPublicKey(__DIR__ . '/../../../../assets/keys/rsa-public.pem');
    }

    /**
     * EMSA-PSS is randomized: every signature embeds a fresh salt, so two signatures over the same message must
     * differ while both stay verifiable.
     *
     * @throws Throwable
     */
    public function test_sign_twice_it_should_produce_distinct_valid_signatures()
    {
        $signer = new PS256Signer($this->rsaPrivateKey);
        $verifier = new PS256Verifier($this->rsaPublicKey);

        $first = $signer->sign('Text');
        $second = $signer->sign('Text');

        $this->assertNotSame($first, $second);

        $verifier->verify('Text', $first);
        $verifier->verify('Text', $second);
    }

    /**
     * @throws Throwable
     */
    public function test_sign_it_should_produce_a_signature_of_the_modulus_size()
    {
        $signer = new PS256Signer($this->rsaPrivateKey);

        $this->assertSame(256, strlen($signer->sign('Text')));
    }

    /**
     * With the salt pinned, the whole EMSA-PSS encode path is deterministic and must reproduce the expected
     * signature byte for byte (see the constant above for how the vector was cross-checked).
     *
     * @throws Throwable
     */
    public function test_sign_with_a_fixed_salt_it_should_produce_the_expected_signature()
    {
        $signer = new class (new RsaPrivateKey(KeyFixtures::PRIVATE_KEY_2041)) extends PS256Signer {
            protected function salt(int $length): string
            {
                return str_repeat("\xAB", $length);
            }
        };

        $this->assertSame((string)base64_decode(self::FIXED_SALT_SIGNATURE_2041), $signer->sign('Text'));
    }

    /**
     * The exception surfaces the pending OpenSSL error instead of the generic fallback message. Whether a failed
     * raw operation queues an error of its own varies by platform, so the queue is drained and re-seeded with a
     * known error to make its state deterministic.
     *
     * @throws Throwable
     */
    public function test_sign_with_a_wrong_modulus_size_it_should_carry_the_openssl_error()
    {
        $signer = new class ($this->rsaPrivateKey) extends PS256Signer {
            protected function modulusBits($key): int
            {
                return 2128; // 266-byte encoded message: too large for the raw RSA operation on a 2048-bit key
            }
        };

        while (openssl_error_string() !== false) {
            continue;
        }
        openssl_pkey_get_private('not-a-valid-key');

        try {
            $signer->sign('Text');
            $this->fail('A SigningException was expected.');
        } catch (SigningException $e) {
            $this->assertStringStartsWith('error:', $e->getMessage());
        }
    }
}
