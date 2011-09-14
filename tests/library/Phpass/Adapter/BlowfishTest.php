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
 * @version 0.5
 */

/**
 * @namespace
 */
namespace Phpass\Adapter;
use Phpass\Adapter\Blowfish;

/**
 * @see PHPUnit_Framework_TestCase
 */
require_once 'PHPUnit/Framework/TestCase.php';

/**
 * @see Phpass\Adapter\Blowfish
 */
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
 * @version 0.5
 */
class BlowfishTest extends \PHPUnit_Framework_TestCase
{

    /**
     * @var Phpass\Adapter
     */
    protected $_adapter;

    /**
     * (non-PHPdoc)
     * @see PHPUnit_Framework_TestCase::setUp()
     */
    protected function setUp()
    {
        $this->_adapter = new Blowfish;
        if (!$this->_adapter->isSupported()) {
            $this->markTestSkipped('This system lacks required support.');
        }
    }

    /**
     * Test that adapter generates a valid salt
     *
     * The blowfish adapter should generate a 29-character salt string which
     * begins with $2a$ followed by a two-digit iteration count.
     *
     * By default, the adapter should use an iteration count of 8, so the salt
     * string should look like $2a$08$..., so that's what we test for.
     *
     * @test
     * @return string
     */
    public function adapterGeneratesValidSalt()
    {
        $salt = $this->_adapter->genSalt();

        // Salt begins with correct string
        $this->assertStringStartsWith(
            '$2a$08$', // Expected
            $salt  // Actual
        );

        // Salt has proper length
        $this->assertEquals(
            29, // Expected
            strlen($salt) // Actual
        );

        return $salt;
    }

    /**
     * Test that the adapter generates a valid hash
     *
     * The blowfish adapter should generate a 60-character hash which begins
     * with the salt.
     *
     * This test depends on the salt test, and uses the output of that test.
     * This way, the test focuses on the hash, and won't be affected by the call
     * to Phpass\Adapter::genSalt().
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
            60, // Expected
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