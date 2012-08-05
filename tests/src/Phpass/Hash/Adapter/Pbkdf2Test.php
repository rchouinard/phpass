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

namespace Phpass\Hash\Adapter;

use \PHPUnit_Framework_TestCase as TestCase;

/**
 * PHP Password Library
 *
 * @package PHPass\Tests
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
class Pbkdf2Test extends TestCase
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
     * @return array
     */
    public function validTestVectorProvider()
    {
        $vectors = array (
            // Generated using the Python PassLib
            array ("password", '$pbkdf2$1212$OB.dtnSEXZK8U5cgxU/GYQ$y5LKPOplRmok7CZp/aqVDVg8zGI'),
            array ("password", '$pbkdf2-sha256$1212$4vjV83LKPjQzk31VI4E0Vw$hsYF68OiOUPdDZ1Fg.fJPeq1h/gXXY7acBp9/6c.tmQ'),
            array ("password", '$pbkdf2-sha512$1212$RHY0Fr3IDMSVO/RSZyb5ow$eNLfBK.eVozomMr.1gYa17k9B7KIK25NOEshvhrSX.esqY3s.FvWZViXz4KoLlQI.BzY/YTNJOiKc5gBYFYGww'),
        );

        return $vectors;
    }

    /**
     * @return array
     */
    public function invalidTestVectorProvider()
    {
        $vectors = array (
            array ("", '$pbkdf2$01212$THDqatpidANpadlLeTeOEg$HV3oi1k5C5LQCgG1BMOL.BX4YZc', '*0'),
            array ("", '*0', '*1'),
            array ("", '*1', '*0'),
        );

        return $vectors;
    }

    /**
     * @test
     * @dataProvider rfc6070TestVectorProvider
     */
    public function pbkdf2MethodPassesUsingRfc6070TestVectors($input, $output)
    {
        $class = new \ReflectionClass('Phpass\\Hash\\Adapter\\Pbkdf2');
        $method = $class->getMethod('_pbkdf2');
        $method->setAccessible(true);

        $adapter = new Pbkdf2;

        $this->assertEquals(
            $output, // Expected
            bin2hex($method->invokeArgs($adapter, $input)) // Actual
        );
    }

    /**
     * @test
     * @dataProvider validTestVectorProvider
     */
    public function validTestVectorsProduceExpectedResults($password, $hash)
    {
        $this->assertEquals($hash, $this->_adapter->crypt($password, $hash));
    }

    /**
     * @test
     * @dataProvider invalidTestVectorProvider
     */
    public function invalidTestVectorsProduceExpectedResults($password, $hash, $errorString)
    {
        $this->assertEquals($errorString, $this->_adapter->crypt($password, $hash));
    }

}
