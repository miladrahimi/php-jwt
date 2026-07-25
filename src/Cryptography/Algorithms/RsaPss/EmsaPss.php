<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\RsaPss;

use function hash;
use function intdiv;
use function is_array;
use function is_int;
use function pack;
use function strlen;
use function substr;

/**
 * EMSA-PSS primitives (RFC 8017) shared by the RSA-PSS signer and verifier.
 *
 * PHP's `openssl_sign`/`openssl_verify` only support PKCS#1 v1.5 padding, so the PSS encoding is produced and
 * checked here, and only the raw RSA operation (`OPENSSL_NO_PADDING`) is delegated to OpenSSL.
 */
trait EmsaPss
{
    /**
     * Returns the hash algorithm name behind the JWA name (provided by the `Algorithm` trait).
     */
    abstract protected function algorithm(): string;

    /**
     * Hashes the data with the algorithm's hash function (raw binary output).
     */
    protected function digest(string $data): string
    {
        return hash($this->algorithm(), $data, true);
    }

    /**
     * Returns the byte length of the algorithm's hash output (RFC 8017 `hLen`).
     *
     * @phpstan-return positive-int
     */
    protected function hashLength(): int
    {
        return [
            'sha256' => 32,
            'sha384' => 48,
            'sha512' => 64,
        ][$this->algorithm()];
    }

    /**
     * Generates a mask of the given length from the seed, per the MGF1 mask generation function (RFC 8017 §B.2.1)
     * with the algorithm's hash function.
     */
    protected function mgf1(string $seed, int $length): string
    {
        $mask = '';
        $counter = 0;

        while (strlen($mask) < $length) {
            $mask .= $this->digest($seed . pack('N', $counter));
            $counter++;
        }

        return substr($mask, 0, $length);
    }

    /**
     * Reads the RSA modulus size in bits from the OpenSSL key handle, or 0 when the size cannot be determined
     * (the callers then reject the key or the signature).
     *
     * @param resource|\OpenSSLAsymmetricKey $key The OpenSSL key handle.
     * @phpstan-param resource $key
     */
    protected function modulusBits($key): int
    {
        /** @var array<string, mixed>|false $details openssl_pkey_get_details() returns false on failure. */
        $details = openssl_pkey_get_details($key);
        if (!is_array($details) || !is_int($details['bits'] ?? null)) {
            // @codeCoverageIgnoreStart
            return 0;
            // @codeCoverageIgnoreEnd
        }

        return $details['bits'];
    }

    /**
     * Returns the byte length of an EMSA-PSS encoded message (RFC 8017 `emLen = \ceil(emBits / 8)`).
     */
    protected function encodedMessageLength(int $emBits): int
    {
        return intdiv($emBits + 7, 8);
    }
}
