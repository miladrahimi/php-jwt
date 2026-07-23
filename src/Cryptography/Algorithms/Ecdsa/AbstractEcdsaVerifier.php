<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa;

use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPublicKey;
use MiladRahimi\Jwt\Cryptography\Verifier;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;

use function chr;
use function ltrim;
use function ord;
use function str_split;
use function strlen;

abstract class AbstractEcdsaVerifier implements Verifier
{
    use Algorithm;

    protected const ASN1_INTEGER = 0x02;
    protected const ASN1_SEQUENCE = 0x10;

    protected EcdsaPublicKey $publicKey;

    public function __construct(EcdsaPublicKey $publicKey)
    {
        $this->publicKey = $publicKey;
    }

    /**
     * {@inheritDoc}
     */
    public function verify(string $plain, string $signature): void
    {
        $signature = $this->signatureToDer($signature);
        if (openssl_verify($plain, $signature, $this->publicKey->getResource(), $this->algorithm()) !== 1) {
            throw new InvalidSignatureException(openssl_error_string() ?: 'The signature is invalid.');
        }
    }

    /**
     * Converts a raw `R || S` JWS signature (RFC 7518) into the DER-encoded
     * form that OpenSSL expects: an ASN.1 SEQUENCE of two INTEGERs (r, s).
     */
    protected function signatureToDer(string $signature): string
    {
        $length = max(1, (int) (strlen($signature) / 2));
        [$r, $s] = str_split($signature, $length);      // split the raw signature into its two halves

        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");

        // ASN.1 INTEGERs are signed: prepend 0x00 when the top bit is set so
        // the value is not misread as negative.
        if (ord($r[0]) > 0x7F) {
            $r = "\x00".$r;
        }
        if (ord($s[0]) > 0x7F) {
            $s = "\x00".$s;
        }

        return $this->encodeDer(
            self::ASN1_SEQUENCE,
            $this->encodeDer(self::ASN1_INTEGER, $r).$this->encodeDer(self::ASN1_INTEGER, $s),
        );
    }

    /**
     * Wraps a value in a DER type-length-value envelope.
     *
     * Only the short-form length is emitted, which is sufficient here because
     * ECDSA signature integers never exceed 127 bytes.
     */
    protected function encodeDer(int $type, string $value): string
    {
        $tagHeader = 0;
        if ($type === self::ASN1_SEQUENCE) {
            $tagHeader |= 0x20;                          // mark the tag as constructed
        }

        $der = chr($tagHeader | $type);
        $der .= chr(strlen($value));

        return $der.$value;
    }

    /**
     * {@inheritDoc}
     */
    public function kid(): ?string
    {
        return $this->publicKey->getId();
    }

    public function getPublicKey(): EcdsaPublicKey
    {
        return $this->publicKey;
    }
}
