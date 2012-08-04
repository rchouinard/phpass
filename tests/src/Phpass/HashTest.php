<?php
/**
 * PHP Password Library
 *
 * @package PHPass
 * @subpackage Tests
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */

/**
 * @namespace
 */
namespace Phpass;

/**
 * PHP Password Library
 *
 * @package PHPass
 * @subpackage Tests
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */
class HashTest extends \PHPUnit_Framework_TestCase
{

    /**
     * @test
     * @return void
     */
    public function defaultInstanceUsesBcryptAdapter()
    {
        $hash = new Hash;

        // Verify adapter instance
        $this->assertInstanceOf(
            'Phpass\\Hash\\Adapter\\Bcrypt', // Expected
            $hash->getAdapter() // Actual
        );

        // Verify adapter configuration
        $property = new \ReflectionProperty('Phpass\\Hash\\Adapter\\Bcrypt', '_iterationCountLog2');
        $property->setAccessible(true);
        $this->assertEquals(
            12, // Expected
            $property->getValue($hash->getAdapter()) // Actual
        );
    }

    /**
     * @test
     * @return void
     */
    public function passingAdapterViaConstructorCorrectlySetsInstance()
    {
        $adapter = new \Phpass\Hash\Adapter\Pbkdf2;
        $hash = new Hash($adapter);

        $this->assertInstanceOf(
            'Phpass\\Hash\\Adapter\\Pbkdf2', // Expected
            $hash->getAdapter() // Actual
        );
    }

    /**
     * @test
     * @return void
     */
    public function passingOptionsViaConstructorCorrectlySetsProperties()
    {
        $hash = new Hash(array (
            'adapter' => new \Phpass\Hash\Adapter\Pbkdf2,
            'hmacKey' => 'My53cr3tK3y',
            'hmacAlgo' => 'sha512'
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

    /**
     * @test
     * @return void
     */
    public function hashPasswordMethodReturnsDifferentHashGivenSameInput()
    {
        $password = 'password';
        $hash = new Hash;

        $passwordHash = $hash->hashPassword($password);
        $this->assertEquals('$2y$', substr($passwordHash, 0, 4));
        $this->assertTrue($hash->checkPassword($password, $passwordHash));

        $oldPasswordHash = $passwordHash;
        $passwordHash = $hash->hashPassword($password);
        $this->assertNotEquals($passwordHash, $oldPasswordHash);
        $this->assertEquals('$2y$', substr($passwordHash, 0, 4));
        $this->assertTrue($hash->checkPassword($password, $passwordHash));
    }

    /**
     * @test
     * @return void
     */
    public function hashPasswordMethodUsesHmacIfSoConfigured()
    {
        $password = 'password';
        $hmacKey = 'My53cr3tK3y';

        // Generate and confirm a non-HMAC hash.
        $hash = new Hash;
        $standardPasswordHash = $hash->hashPassword($password);
        $this->assertTrue($hash->checkPassword($password, $standardPasswordHash));

        // Generate and confirm an HMAC hash.
        $hmacHash = new Hash(array ('hmacKey' => $hmacKey));
        $hmacPasswordHash = $hmacHash->hashPassword($password);
        $this->assertTrue($hmacHash->checkPassword($password, $hmacPasswordHash));

        // Non-HMAC hash should not verify with HMAC-configured instance,
        // even given the same password input.
        $this->assertFalse($hmacHash->checkPassword($password, $standardPasswordHash));
        $this->assertFalse($hash->checkPassword($password, $hmacPasswordHash));
    }

}