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
class ExtDesTest extends TestCase
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
     * @return array
     */
    public function validTestVectorProvider()
    {
        $vectors = array (
            // From John the Ripper 1.7.9
            array ("U*U*U*U*", '_J9..CCCCXBrJUJV154M'),
            array ("U*U***U", '_J9..CCCCXUhOBTXzaiE'),
            array ("U*U***U*", '_J9..CCCC4gQ.mB/PffM'),
            array ("*U*U*U*U", '_J9..XXXXvlzQGqpPPdk'),
            array ("*U*U*U*U*", '_J9..XXXXsqM/YSSP..Y'),
            array ("*U*U*U*U*U*U*U*U", '_J9..XXXXVL7qJCnku0I'),
            array ("*U*U*U*U*U*U*U*U*", '_J9..XXXXAj8cFbP5scI'),
            array ("ab1234567", '_J9..SDizh.vll5VED9g'),
            array ("cr1234567", '_J9..SDizRjWQ/zePPHc'),
            array ("zxyDPWgydbQjgq", '_J9..SDizxmRI1GjnQuE'),
            array ("726 even", '_K9..SaltNrQgIYUAeoY'),
            array ("", '_J9..SDSD5YGyRCr4W4c'),
        );

        return $vectors;
    }

    /**
     * @return array
     */
    public function invalidTestVectorProvider()
    {
        $vectors = array (
            array ("", '_K1.!crsmZxOLzfJH8iw', '*0'),
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
        $config = substr($hash, 0, 9);
        $this->assertEquals($hash, $this->_adapter->crypt($password, $config));
    }

    /**
     * @test
     * @dataProvider invalidTestVectorProvider
     */
    public function invalidTestVectorsProduceExpectedResults($password, $hash, $errorString)
    {
        $config = substr($hash, 0, 9);
        $this->assertEquals($errorString, $this->_adapter->crypt($password, $config));
    }

}
