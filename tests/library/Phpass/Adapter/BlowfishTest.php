<?php
/**
 * Portable PHP password hashing framework.
 *
 * @package PHPass
 * @subpackage Tests
 * @category Cryptography
 * @author Solar Designer <solar at openwall.com>
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license Public Domain
 * @link http://www.openwall.com/phpass/ Original phpass project page.
 * @version 0.4
 */

require_once 'PHPUnit/Framework/TestCase.php';
require_once 'Phpass/Adapter/Blowfish.php';

/**
 * Portable PHP password hashing framework.
 *
 * @package PHPass
 * @subpackage Tests
 * @category Cryptography
 * @author Solar Designer <solar at openwall.com>
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license Public Domain
 * @link http://www.openwall.com/phpass/ Original phpass project page.
 * @version 0.4
 */
class Phpass_Adapter_BlowfishTest extends PHPUnit_Framework_TestCase
{

    /**
     * @var Phpass_Adapter
     */
    protected $_adapter;

    /**
     * (non-PHPdoc)
     * @see PHPUnit_Framework_TestCase::setUp()
     */
    protected function setUp()
    {
        if (!CRYPT_BLOWFISH) {
            $this->markTestSkipped('This system lacks Blowfish support.');
        }

        $this->_adapter = new Phpass_Adapter_Blowfish;
    }

    /**
     * @test
     * @return string
     */
    public function generatedSaltSuitableForHashMethod()
    {
        $salt = $this->_adapter->genSalt();

        $this->assertStringStartsWith(
            '$2a$08$', // Expected
            $salt,  // Actual
            'Generated salt should begin with \'$2a$08$\' with default adapter options.'
        );

        $this->assertEquals(
            29, // Expected
            strlen($salt), // Actual
            'Generated salt should be 29 characters in length.'
        );

        return $salt;
    }

    /**
     * @test
     * @depends generatedSaltSuitableForHashMethod
     * @return string
     */
    public function generatedHashShouldBeProperLength($salt)
    {
        $hash = $this->_adapter->crypt('password', $salt);

        $this->assertEquals(
            60, // Expected
            strlen($hash), // Actual
            'Generated hash should be 60 characters in length.'
        );

        $this->assertStringStartsWith(
            $salt, // Expected
            $hash, // Actual
            'Generated hash string should begin with salt.'
        );

        return $hash;
    }

    /**
     * @test
     * @depends generatedHashShouldBeProperLength
     * @return void
     */
    public function adapterCanVerifyHash($storedHash)
    {
        $hash = $this->_adapter->crypt('password', $storedHash);

        $this->assertEquals(
            $storedHash, // Expected
            $hash, // Actual
            'Crypt method should generate the same hash given the original password and hash as salt.'
        );
    }

}