<?php
/**
 * Created by PhpStorm.
 * User: Milad Rahimi <info@miladrahimi.com>
 * Date: 5/14/2018 AD
 * Time: 22:23
 */

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Rsa;

use MiladRahimi\Jwt\Base64\Base64ParserInterface;
use MiladRahimi\Jwt\Cryptography\AbstractVerifier;
use MiladRahimi\Jwt\Cryptography\Keys\PublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;

abstract class AbstractRsaVerifier extends AbstractVerifier
{
    use Naming;

    /**
     * @var PublicKey
     */
    protected $publicKey;

    /**
     * AbstractRsaVerifier constructor.
     *
     * @param PublicKey $key
     * @param Base64ParserInterface|null $base64Parser
     */
    public function __construct(PublicKey $key, Base64ParserInterface $base64Parser = null)
    {
        $this->setPublicKey($key);

        parent::__construct($base64Parser);
    }

    /**
     * @inheritdoc
     */
    public function verify(string $header, string $payload, string $signature)
    {
        $data = $header . '.' . $payload;
        $signature = $this->base64Parser->decode($signature);

        if (openssl_verify($data, $signature, $this->publicKey->getResource(), $this->algorithmName()) == false) {
            throw new InvalidSignatureException();
        }
    }

    /**
     * @return PublicKey
     */
    public function getPublicKey(): PublicKey
    {
        return $this->publicKey;
    }

    /**
     * @param PublicKey $publicKey
     */
    public function setPublicKey(PublicKey $publicKey)
    {
        $this->publicKey = $publicKey;
    }
}