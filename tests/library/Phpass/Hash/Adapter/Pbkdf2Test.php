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
class Pbkdf2Test extends \PHPUnit_Framework_TestCase
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
        $this->_adapter = new Pbkdf2;
    }

    /**
     * @return array
     */
    public function rfc6070TestVectorProvider()
    {
        return array (
            array (
                array (
                    'P'     => 'password',
                    'S'     => 'salt',
                    'c'     => 1,
                    'dkLen' => 20
                ),
                '0c60c80f961f0e71f3a9b524af6012062fe037a6'
            ),
            array (
                array (
                    'P'     => 'password',
                    'S'     => 'salt',
                    'c'     => 2,
                    'dkLen' => 20
                ),
                'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957'
            ),
            array (
                array (
                    'P'     => 'password',
                    'S'     => 'salt',
                    'c'     => 4096,
                    'dkLen' => 20
                ),
                '4b007901b765489abead49d926f721d065a429c1'
            ),
            // Takes a long time to run :-)
            //array (
            //    array (
            //        'P'     => 'password',
            //        'S'     => 'salt',
            //        'c'     => 16777216,
            //        'dkLen' => 20
            //    ),
            //    'eefe3d61cd4da4e4e9945b3d6ba2158c2634e984'
            //),
            array (
                array (
                    'P'     => 'passwordPASSWORDpassword',
                    'S'     => 'saltSALTsaltSALTsaltSALTsaltSALTsalt',
                    'c'     => 4096,
                    'dkLen' => 25
                ),
                '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038'
            ),
            array (
                array (
                    'P'     => "pass\0word",
                    'S'     => "sa\0lt",
                    'c'     => 4096,
                    'dkLen' => 16
                ),
                '56fa6aa75548099dcc37d7f03425e0c3'
            )
        );
    }

    /**
     * Test PBKDF2 implementation
     *
     * Uses test vectors from RFC 6070
     *
     * @test
     * @dataProvider rfc6070TestVectorProvider
     * @return void
     */
    public function pbkdf2MethodPassesUsingRfc6070TestVectors($input, $output)
    {
        $class = new \ReflectionClass('Phpass\Hash\Adapter\Pbkdf2');
        $method = $class->getMethod('_pbkdf2');
        $method->setAccessible(true);

        $adapter = new Pbkdf2;

        $this->assertEquals(
            $output, // Expected
            bin2hex($method->invokeArgs($adapter, $input)) // Actual
        );
    }

    /**
     * Test that adapter generates a valid salt
     *
     * The portable adapter should generate a 16-character salt string which
     * begins with $p5v2$ followed by 1 byte of iteration count and 8 bytes of
     * salt.
     *
     * By default, the adapter should use an iteration count of 12, so the salt
     * string should look like $p5v2$A..., so that's what we test for.
     *
     * @test
     * @return string
     */
    public function adapterGeneratesValidSalt()
    {
        $salt = $this->_adapter->genSalt();

        // Salt begins with correct string
        $this->assertStringStartsWith(
            '$p5v2$A', // Expected
            $salt  // Actual
        );

        // Salt has proper length
        $this->assertEquals(
            16, // Expected
            strlen($salt) // Actual
        );

        return $salt;
    }

    /**
     * Test that the adapter generates a valid hash
     *
     * The pbkdf2 adapter should generate a 48-character hash which begins
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
            48, // Expected
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