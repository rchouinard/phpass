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
namespace Phpass\Hash\Adapter;

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
class PortableTest extends \PHPUnit_Framework_TestCase
{

    /**
     * @var Phpass\Hash\Adapter
     */
    protected $_adapter;

    /**
     * (non-PHPdoc)
     * @see PHPUnit_Framework_TestCase::setUp()
     */
    protected function setUp()
    {
        $this->_adapter = new Portable;
    }

    /**
     * Test that adapter generates a valid salt
     *
     * The portable adapter should generate a 12-character salt string which
     * begins with $P$ followed by 1 byte of iteration count and 8 bytes of
     * salt.
     *
     * By default, the adapter should use an iteration count of 12, so the salt
     * string should look like $P$F..., so that's what we test for.
     *
     * @test
     * @return string
     */
    public function adapterGeneratesValidSalt()
    {
        $salt = $this->_adapter->genSalt();

        // Salt begins with correct string
        $this->assertStringStartsWith(
            '$P$F', // Expected
            $salt  // Actual
        );

        // Salt has proper length
        $this->assertEquals(
            12, // Expected
            strlen($salt) // Actual
        );

        return $salt;
    }

    /**
     * Test that the adapter generates a valid hash
     *
     * The portable adapter should generate a 34-character hash which begins
     * with the salt.
     *
     * This test depends on the salt test, and uses the output of that test.
     * This way, the test focuses on the hash, and won't be affected by the call
     * to Phpass\Hash::genSalt().
     *
     * @test
     * @depends adapterGeneratesValidSalt
     * @return string
     */
    public function adapterGeneratesValidHash($salt)
    {
        $hash = $this->_adapter->crypt('password', $salt);

        // Hash string begins with salt
        $this->assertStringStartsWith(
            $salt, // Expected
            $hash // Actual
        );

        // Hash string has proper length
        $this->assertEquals(
            34, // Expected
            strlen($hash) // Actual
        );

        return $hash;
    }

    /**
     * Test that the adapter generates the same hash given the same input
     *
     * The adapter should be consistent with hash generation given the same
     * input parameters, otherwise the adapter won't be able to actually
     * validate a password (making it useless).
     *
     * This test uses the output of the hash test in order to be consistent and
     * focus on validation.
     *
     * @test
     * @depends adapterGeneratesValidHash
     * @return void
     */
    public function adapterGeneratesSameHashGivenOriginalSaltAndPasswordString($storedHash)
    {
        $hash = $this->_adapter->crypt('password', $storedHash);

        // Generated hash matches stored hash value
        $this->assertEquals(
            $storedHash, // Expected
            $hash // Actual
        );
    }

}