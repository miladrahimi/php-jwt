<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\RsaPss;

use MiladRahimi\Jwt\Cryptography\Keys\RsaPublicKey;
use MiladRahimi\Jwt\Cryptography\NamedVerifier;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;

use function chr;
use function hash_equals;
use function is_string;
use function ord;
use function str_repeat;
use function strlen;
use function substr;

abstract class AbstractRsaPssVerifier implements NamedVerifier
{
    use Algorithm;
    use EmsaPss;

    /**
     * The one message every verification inconsistency raises, so the outcome reveals nothing about where the
     * check failed.
     */
    private const INVALID_SIGNATURE_MESSAGE = 'The signature is not valid.';

    protected RsaPublicKey $publicKey;

    public function __construct(RsaPublicKey $publicKey)
    {
        $this->publicKey = $publicKey;
    }

    /**
     * {@inheritDoc}
     *
     * Implements RSASSA-PSS-VERIFY (RFC 8017 §8.1.2): the raw RSA public-key operation recovers the encoded
     * message, which is then checked against EMSA-PSS. Every inconsistency raises the same generic exception,
     * so the outcome reveals nothing about where the check failed.
     */
    public function verify(string $plain, string $signature): void
    {
        $modulusBits = $this->modulusBits($this->publicKey->getResource());
        $modulusLength = $this->encodedMessageLength($modulusBits);

        if (strlen($signature) !== $modulusLength) {
            throw new InvalidSignatureException('The signature length is not valid.');
        }

        $recovered = $this->recover($signature);

        // The encoded message is emLen = ceil((modBits - 1) / 8) bytes; when the modulus size is a multiple of
        // eight bits (every common RSA key), that equals the modulus size and no leading zero byte is expected.
        $emLength = $this->encodedMessageLength($modulusBits - 1);
        $padding = substr($recovered, 0, $modulusLength - $emLength);
        if ($padding !== str_repeat("\x00", $modulusLength - $emLength)) {
            throw new InvalidSignatureException(self::INVALID_SIGNATURE_MESSAGE);
        }

        if (!$this->isConsistent($plain, substr($recovered, $modulusLength - $emLength), $modulusBits - 1)) {
            throw new InvalidSignatureException(self::INVALID_SIGNATURE_MESSAGE);
        }
    }

    /**
     * Recovers the encoded message from the signature with the raw RSA public-key operation.
     *
     * @throws InvalidSignatureException
     */
    protected function recover(string $signature): string
    {
        $recovered = null;
        if (
            openssl_public_decrypt($signature, $recovered, $this->publicKey->getResource(), OPENSSL_NO_PADDING)
            && is_string($recovered)
        ) {
            return $recovered;
        }

        throw new InvalidSignatureException(openssl_error_string() ?: self::INVALID_SIGNATURE_MESSAGE);
    }

    /**
     * Checks the recovered encoded message against EMSA-PSS (RFC 8017 §9.1.2), using the algorithm's hash
     * function and a salt of the same length as its output, as RFC 7518 §3.5 requires for the PS* algorithms.
     */
    protected function isConsistent(string $message, string $encoded, int $emBits): bool
    {
        $hashLength = $this->hashLength();
        $saltLength = $hashLength;
        $emLength = $this->encodedMessageLength($emBits);

        // The data block needs the salt and its 0x01 separator, so emLen >= hLen + sLen + 2 (RFC 8017 §9.1.2),
        // and the encoded message must have the expected length and end with the 0xBC trailer byte.
        $dbLength = $emLength - $hashLength - 1;
        if ($dbLength < $saltLength + 1 || strlen($encoded) !== $emLength || substr($encoded, -1) !== "\xBC") {
            return false;
        }

        $maskedDb = substr($encoded, 0, $dbLength);
        $hash = substr($encoded, $dbLength, $hashLength);

        // The leftmost 8 * emLen - emBits bits of the masked data block must be zero.
        $clearBits = 8 * $emLength - $emBits;
        if ((ord($maskedDb[0]) & ~(0xFF >> $clearBits)) !== 0) {
            return false;
        }

        $db = $maskedDb ^ $this->mgf1($hash, strlen($maskedDb));
        $db[0] = chr(ord($db[0]) & (0xFF >> $clearBits));

        return $this->isDataBlockConsistent($message, $db, $hash);
    }

    /**
     * Checks the unmasked data block (RFC 8017 §9.1.2 steps 10-14): zero padding, a 0x01 separator, then the
     * salt, whose hash together with the message must reproduce the hash carried by the encoded message.
     */
    protected function isDataBlockConsistent(string $message, string $db, string $hash): bool
    {
        $paddingLength = strlen($db) - $this->hashLength() - 1;
        if (substr($db, 0, $paddingLength) !== str_repeat("\x00", $paddingLength)) {
            return false;
        }
        if ($db[$paddingLength] !== "\x01") {
            return false;
        }

        $salt = substr($db, $paddingLength + 1);
        $expected = $this->digest(str_repeat("\x00", 8) . $this->digest($message) . $salt);

        return hash_equals($expected, $hash);
    }

    /**
     * {@inheritDoc}
     */
    public function kid(): ?string
    {
        return $this->publicKey->getId();
    }

    public function getPublicKey(): RsaPublicKey
    {
        return $this->publicKey;
    }
}
