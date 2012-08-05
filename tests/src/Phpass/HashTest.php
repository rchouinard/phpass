<?php
/**
 * PHP Password Library
 *
 * @package PHPass\Tests
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */

namespace Phpass;

use \PHPUnit_Framework_TestCase as TestCase;
use Phpass\Hash\Adapter\Pbkdf2;

/**
 * PHP Password Library
 *
 * @package PHPass\Tests
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
class HashTest extends TestCase
{

    /**
     * @test
     */
    public function defaultInstanceUsesBcryptAdapter()
    {
        $hash = new Hash;
        $this->assertInstanceOf(
            'Phpass\\Hash\\Adapter\\Bcrypt', // Expected
            $hash->getAdapter() // Actual
        );
    }

    /**
     * @test
     */
    public function passingAdapterViaConstructorCorrectlySetsInstance()
    {
        $hash = new Hash(new Pbkdf2);
        $this->assertInstanceOf(
            'Phpass\\Hash\\Adapter\\Pbkdf2', // Expected
            $hash->getAdapter() // Actual
        );
    }

    /**
     * @test
     */
    public function passingOptionsViaConstructorCorrectlySetsProperties()
    {
        $hash = new Hash(array (
            'adapter' => new Pbkdf2,
            'hmacKey' => 'My53cr3tK3y',
            'hmacAlgo' => 'sha512',
        ));

        $this->assertInstanceOf(
            'Phpass\\Hash\\Adapter\\Pbkdf2', // Expected
            $hash->getAdapter() // Actual
        );

        $property = new \ReflectionProperty('Phpass\\Hash', '_hmacKey');
        $property->setAccessible(true);
        $this->assertEquals(
            'My53cr3tK3y', // Expected
            $property->getValue($hash) // Actual
        );

        $property = new \ReflectionProperty('Phpass\\Hash', '_hmacAlgo');
        $property->setAccessible(true);
        $this->assertEquals(
            'sha512', // Expected
            $property->getValue($hash) // Actual
        );
    }

}
