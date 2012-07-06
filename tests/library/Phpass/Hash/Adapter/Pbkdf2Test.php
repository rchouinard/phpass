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

/**
 * @namespace
 */
namespace Phpass\Hash\Adapter;

/**
 * PBKDF2 hash adapter tests
 *
 * @package PHPass\Tests
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
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
     * Run a number of standard test vectors through the adapter
     *
     * This tests the underlying crypt() method more than anything, but it's
     * a good idea to make sure the adapter doesn't inadvertently interfere.
     *
     * @test
     * @return void
     */
    public function knownTestVectorsBehaveAsExpected()
    {
        $adapter = $this->_adapter;

        $vectors = array (
            array ("password", '$pbkdf2$1212$OB.dtnSEXZK8U5cgxU/GYQ$y5LKPOplRmok7CZp/aqVDVg8zGI'),
            array ("password", '$pbkdf2-sha256$1212$4vjV83LKPjQzk31VI4E0Vw$hsYF68OiOUPdDZ1Fg.fJPeq1h/gXXY7acBp9/6c.tmQ'),
            array ("password", '$pbkdf2-sha512$1212$RHY0Fr3IDMSVO/RSZyb5ow$eNLfBK.eVozomMr.1gYa17k9B7KIK25NOEshvhrSX.esqY3s.FvWZViXz4KoLlQI.BzY/YTNJOiKc5gBYFYGww'),
        );

        foreach ($vectors as $vector) {
            $this->assertEquals($vector[1], $adapter->crypt($vector[0], $vector[1]));
        }

        $this->assertEquals($adapter->crypt('', '*0'), '*1');
        $this->assertEquals($adapter->crypt('', '*1'), '*0');
    }

    /**
     * Test that setOptions() properly sets configuration options
     *
     * @test
     * @return void
     */
    public function modifyingOptionsUpdatesAdapterBehavior()
    {
        $adapter = $this->_adapter;

        $adapter->setOptions(array ('digest' => 'sha1'));
        $this->assertStringStartsWith('$pbkdf2$', $adapter->genSalt());

        $adapter->setOptions(array ('digest' => 'sha256'));
        $this->assertStringStartsWith('$pbkdf2-sha256$', $adapter->genSalt());

        $adapter->setOptions(array ('digest' => 'sha512'));
        $this->assertStringStartsWith('$pbkdf2-sha512$', $adapter->genSalt());

        $adapter->setOptions(array ('iterationCount' => 1212));
        $this->assertStringStartsWith('$pbkdf2-sha512$1212$', $adapter->genSalt());

        $adapter->setOptions(array ('digest' => 'sha256', 'iterationCount' => 5000));
        $this->assertStringStartsWith('$pbkdf2-sha256$5000$', $adapter->genSalt());

        try {
            $adapter->setOptions(array ('digest' => 'invalid'));
        } catch (\Exception $e) {}
        $this->assertInstanceOf('Phpass\\Exception\\InvalidArgumentException', $e);
        unset($e);

        try {
            $adapter->setOptions(array ('iterationCount' => '0'));
        } catch (\Exception $e) {}
        $this->assertInstanceOf('Phpass\\Exception\\InvalidArgumentException', $e);
        unset($e);
    }

    /**
     * Test that the adapter generates a valid hash
     *
     * @test
     * @return void
     */
    public function adapterGeneratesValidHashString()
    {
        $adapter = $this->_adapter;
        $password = 'password';

        // Generates a valid salt string
        $this->assertTrue($adapter->verifySalt($adapter->genSalt()));

        // Generates a valid hash string
        $this->assertTrue($adapter->verifyHash($adapter->crypt($password)));
    }

    /**
     * Test that the adapter generates the same hash given the same input
     *
     * @test
     * @return void
     */
    public function adapterConsistentlyGeneratesHashStrings()
    {
        $adapter = $this->_adapter;
        $password = 'password';

        $salt = $adapter->genSalt();
        $hash = $adapter->crypt($password, $salt);

        // Generates the same hash for the password given the stored salt
        $this->assertEquals($hash, $adapter->crypt($password, $salt));

        // Generates the same hash for the password given the stored hash
        $this->assertEquals($hash, $adapter->crypt($password, $hash));
    }

}