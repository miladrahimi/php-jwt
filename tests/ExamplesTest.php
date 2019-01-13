<?php

namespace MiladRahimi\Jwt\Tests;

use Exception;
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\PrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\PublicKey;
use MiladRahimi\Jwt\JwtGenerator;
use MiladRahimi\Jwt\JwtParser;

class ExamplesTest extends TestCase
{
    /**
     * @throws Exception
     */
    public function testExample1()
    {
        $key = '12345678901234567890123456789012';
        $signer = $verifier = new HS256($key);

        $generator = new JwtGenerator($signer);

        $jwt = $generator->generate(['sub' => 1, 'jti' => 2]);

        $parser = new JwtParser($verifier);

        $claims = $parser->parse($jwt);

        $this->assertSame(['sub' => 1, 'jti' => 2], $claims);
    }

    /**
     * @throws Exception
     */
    public function testExample2()
    {
        $privateKey = new PrivateKey(__DIR__ . '/keys/private.pem');
        $publicKey = new PublicKey(__DIR__ . '/keys/public.pem');

        $signer = new RS256Signer($privateKey);
        $verifier = new RS256Verifier($publicKey);

        $generator = new JwtGenerator($signer);
        $jwt = $generator->generate(['sub' => 1, 'jti' => 2]);

        $parser = new JwtParser($verifier);
        $claims = $parser->parse($jwt);

        $this->assertSame(['sub' => 1, 'jti' => 2], $claims);
    }
}
