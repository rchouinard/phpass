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
class Md5CryptTest extends TestCase
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
        $this->_adapter = new Md5Crypt;
    }

    /**
     * @return array
     */
    public function validTestVectorProvider()
    {
        $vectors = array (
            // From John the Ripper 1.7.9
            array ("0123456789ABCDE", '$1$12345678$aIccj83HRDBo6ux1bVx7D1'),
            array ("12345678", '$1$12345678$f8QoJuo0DpBRfQSD0vglc1'),
            array ("", '$1$$qRPK7m23GJusamGpoGLby/'),
            array ("no salt", '$1$$AuJCr07mI7DSew03TmBIv/'),
            array ("", '$1$12345678$xek.CpjQUVgdf/P2N9KQf/'),
            array ("1234", '$1$1234$BdIMOAWFOV2AQlLsrN/Sw.'),
        );

        return $vectors;
    }

    /**
     * @return array
     */
    public function invalidTestVectorProvider()
    {
        // TODO: Find a good source of test vectors
        $vectors = array (
            array ("invalid salt", '$1$`!@#%^&*$E6hD76/pKTS8qToBCkux30', '*0'),
            array ("", '*0', '*1'),
            array ("", '*1', '*0'),
        );

        return $vectors;
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
