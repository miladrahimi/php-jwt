<?php

namespace MiladRahimi\Jwt\Tests\Cryptography\Keys;

use MiladRahimi\Jwt\Cryptography\Keys\HmacKey;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class HmacKeyTest extends TestCase
{
    /**
     * @throws Throwable
     */
    public function test_with_valid_key_it_should_pass()
    {
        $key = new HmacKey('12345678901234567890123456789012');
        $this->assertNotNull('12345678901234567890123456789012', $key->getContent());
    }

    /**
     * @throws Throwable
     */
    public function test_id()
    {
        $key = new HmacKey('12345678901234567890123456789012', 'id-1');
        $this->assertEquals('id-1', $key->getId());
    }
}
