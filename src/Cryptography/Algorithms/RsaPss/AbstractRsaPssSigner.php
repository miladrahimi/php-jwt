<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\RsaPss;

use Exception;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Signer;
use MiladRahimi\Jwt\Exceptions\SigningException;

use function chr;
use function is_string;
use function ord;
use function random_bytes;
use function str_pad;
use function str_repeat;
use function strlen;

abstract class AbstractRsaPssSigner implements Signer
{
    use Algorithm;
    use EmsaPss;

    protected RsaPrivateKey $privateKey;

    public function __construct(RsaPrivateKey $privateKey)
    {
        $this->privateKey = $privateKey;
    }

    /**
     * {@inheritDoc}
     */
    public function sign(string $message): string
    {
        $modulusBits = $this->modulusBits($this->privateKey->getResource());

        // RSASSA-PSS-SIGN (RFC 8017 §8.1.1): encode with emBits = modBits - 1, then apply the raw RSA private-key
        // operation. The encoded message is left-padded to the modulus size, as I2OSP would zero-extend it.
        $encoded = $this->encode($message, $modulusBits - 1);
        $encoded = str_pad($encoded, $this->encodedMessageLength($modulusBits), "\x00", STR_PAD_LEFT);

        $signature = null;
        if (
            openssl_private_encrypt($encoded, $signature, $this->privateKey->getResource(), OPENSSL_NO_PADDING)
            && is_string($signature)
        ) {
            return $signature;
        }

        throw new SigningException(openssl_error_string() ?: 'OpenSSL cannot sign the token.');
    }

    /**
     * Encodes the message with EMSA-PSS (RFC 8017 §9.1.1), using the algorithm's hash function and a salt of the
     * same length as its output, as RFC 7518 §3.5 requires for the PS* JWS algorithms.
     *
     * @throws SigningException
     */
    protected function encode(string $message, int $emBits): string
    {
        $hashLength = $this->hashLength();
        $saltLength = $hashLength;
        $emLength = $this->encodedMessageLength($emBits);

        if ($emLength < $hashLength + $saltLength + 2) {
            throw new SigningException("The RSA key is too small for the `{$this->name()}` algorithm.");
        }

        $salt = $this->salt($saltLength);
        $hash = $this->digest(str_repeat("\x00", 8) . $this->digest($message) . $salt);

        $db = str_repeat("\x00", $emLength - $saltLength - $hashLength - 2) . "\x01" . $salt;
        $maskedDb = $db ^ $this->mgf1($hash, strlen($db));

        // Clear the leftmost 8 * emLen - emBits bits so the encoded message stays below 2^emBits.
        $clearBits = 8 * $emLength - $emBits;
        $maskedDb[0] = chr(ord($maskedDb[0]) & (0xFF >> $clearBits));

        return $maskedDb . $hash . "\xBC";
    }

    /**
     * Generates the random salt for one signature.
     *
     * @phpstan-param positive-int $length
     * @throws SigningException
     */
    protected function salt(int $length): string
    {
        try {
            return random_bytes($length);
            // @codeCoverageIgnoreStart
        } catch (Exception $e) {
            throw new SigningException('No source of randomness is available.', 0, $e);
        }
        // @codeCoverageIgnoreEnd
    }

    /**
     * {@inheritDoc}
     */
    public function kid(): ?string
    {
        return $this->privateKey->getId();
    }

    public function getPrivateKey(): RsaPrivateKey
    {
        return $this->privateKey;
    }
}
