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
require_once 'Phpass/Adapter/Portable.php';

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
class Phpass_Adapter_PortableTest extends PHPUnit_Framework_TestCase
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
        $this->_adapter = new \Phpass\Adapter\Portable;
    }

    /**
     * @test
     * @return string
     */
    public function generatedSaltSuitableForHashMethod()
    {
        $salt = $this->_adapter->genSalt();

        $this->assertStringStartsWith(
            '$P$', // Expected
            $salt,  // Actual
            'Generated salt should begin with \'$P$\' with default adapter options.'
        );

        $this->assertEquals(
            12, // Expected
            strlen($salt), // Actual
            'Generated salt should be 12 characters in length.'
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
            34, // Expected
            strlen($hash), // Actual
            'Generated hash should be 34 characters in length.'
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