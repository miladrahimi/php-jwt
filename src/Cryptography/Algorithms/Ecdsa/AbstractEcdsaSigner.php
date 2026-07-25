<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa;

use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Signer;
use MiladRahimi\Jwt\Exceptions\SigningException;

use function ltrim;
use function ord;
use function str_pad;
use function strlen;
use function substr;

abstract class AbstractEcdsaSigner implements Signer
{
    use Algorithm;

    protected const ASN1_BIT_STRING = 0x03;

    protected EcdsaPrivateKey $privateKey;

    public function __construct(EcdsaPrivateKey $privateKey)
    {
        $this->privateKey = $privateKey;
    }

    /**
     * {@inheritDoc}
     */
    public function sign(string $message): string
    {
        if (
            openssl_sign($message, $signature, $this->privateKey->getResource(), $this->algorithm()) === true
            && is_string($signature)
        ) {
            return $this->derToSignature($signature, $this->coordinateSize());
        }

        throw new SigningException(openssl_error_string() ?: 'OpenSSL cannot sign the token.');
    }

    /**
     * Converts an OpenSSL DER-encoded signature into the raw `R || S` form
     * required by JWS (RFC 7518).
     *
     * OpenSSL emits ECDSA signatures as an ASN.1 SEQUENCE of two INTEGERs
     * (r, s); JWS expects their fixed-length concatenation, each left-padded
     * to the curve's coordinate size in bytes.
     */
    protected function derToSignature(string $der, int $coordinateSize): string
    {
        $i = $this->decodeDer($der)[0]; // descend into the SEQUENCE
        [$i, $r] = $this->decodeDer($der, $i); // r INTEGER
        $s = $this->decodeDer($der, $i)[1]; // s INTEGER

        // Drop the ASN.1 sign padding, then left-pad to the fixed coordinate size.
        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");

        $r = str_pad($r, $coordinateSize, "\x00", STR_PAD_LEFT);
        $s = str_pad($s, $coordinateSize, "\x00", STR_PAD_LEFT);

        return $r . $s;
    }

    /**
     * Reads a single ASN.1 DER element at the given offset.
     *
     * Returns a [nextOffset, value] pair: for a primitive element (such as an
     * INTEGER) the value is its raw content; for a constructed element (such
     * as a SEQUENCE) the value is empty and nextOffset points at the first
     * child, so the caller can descend into it.
     *
     * @return array{0: int, 1: string}
     */
    protected function decodeDer(string $der, int $offset = 0): array
    {
        $pos = $offset;
        $constructed = (ord($der[$pos]) >> 5) & 0x01; // bit 5: constructed vs primitive
        $type = ord($der[$pos++]) & 0x1f; // low 5 bits: tag number
        [$pos, $length] = $this->decodeDerLength($der, $pos);

        return $this->decodeDerValue($der, $pos, $length, $type, $constructed);
    }

    /**
     * Reads the length of a DER element.
     *
     * @return array{0: int, 1: int}
     */
    private function decodeDerLength(string $der, int $offset): array
    {
        $length = ord($der[$offset++]);
        if (!($length & 0x80)) {
            return [$offset, $length];
        }

        return $this->decodeDerLongLength($der, $offset, $length & 0x1f);
    }

    /**
     * Reads a long-form DER length.
     *
     * @return array{0: int, 1: int}
     */
    private function decodeDerLongLength(string $der, int $offset, int $lengthByteCount): array
    {
        $length = 0;
        $size = strlen($der);
        while ($lengthByteCount-- && $offset < $size) {
            $length = ($length << 8) | ord($der[$offset++]);
        }

        return [$offset, $length];
    }

    /**
     * Reads the value of a DER element.
     *
     * @return array{0: int, 1: string}
     */
    private function decodeDerValue(string $der, int $offset, int $length, int $type, int $constructed): array
    {
        if ($type === self::ASN1_BIT_STRING) {
            $offset++; // skip the leading "unused bits" byte
            $length--;
        }

        if (!$constructed || $type === self::ASN1_BIT_STRING) {
            return [$offset + $length, substr($der, $offset, $length)];
        }

        return [$offset, '']; // constructed: leave the offset at the first child
    }

    /**
     * {@inheritDoc}
     */
    public function kid(): ?string
    {
        return $this->privateKey->getId();
    }

    public function getPrivateKey(): EcdsaPrivateKey
    {
        return $this->privateKey;
    }
}
