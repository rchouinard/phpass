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
class ExtDesTest extends \PHPUnit_Framework_TestCase
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
        $this->_adapter = new ExtDes;
    }

    /**
     * Test that adapter generates a valid salt
     *
     * The extdes adapter should generate a 9-character salt string which
     * begins with and underscore followed by 4 bytes of iteration count and
     * 4 bytes of salt. The iteration count is encoded as the characters
     * /0-9A-Za-z/.
     *
     * By default, the adapter should use an iteration count of 12, so the salt
     * string should look like _zzz1..., so that's what we test for.
     *
     * @test
     * @return string
     */
    public function adapterGeneratesValidSalt()
    {
        $salt = $this->_adapter->genSalt();

        // Salt begins with correct string
        $this->assertStringStartsWith(
            '_zzz1', // Expected
            $salt  // Actual
        );

        // Salt has proper length
        $this->assertEquals(
            9, // Expected
            strlen($salt) // Actual
        );

        return $salt;
    }

    /**
     * Test that the adapter generates a valid hash
     *
     * The extdes adapter should generate a 20-character hash which begins
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
            20, // Expected
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