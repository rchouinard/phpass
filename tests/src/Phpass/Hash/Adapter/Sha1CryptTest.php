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
class Sha1CryptTest extends TestCase
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
        $this->_adapter = new Sha1Crypt;
    }

    /**
     * @return array
     */
    public function validTestVectorProvider()
    {
        $vectors = array (
                array ("password", '$sha1$40000$jtNX3nZ2$hBNaIXkt4wBI2o5rsi8KejSjNqIq'),
                array ("password", '$sha1$19703$iVdJqfSE$v4qYKl1zqYThwpjJAoKX6UvlHq/a'),
                array ("password", '$sha1$21773$uV7PTeux$I9oHnvwPZHMO0Nq6/WgyGV/tDJIH'),
                array ("test", '$sha1$1$Wq3GL2Vp$C8U25GvfHS8qGHimExLaiSFlGkAe'),
        );

        return $vectors;
    }

    /**
     * @return array
     */
    public function invalidTestVectorProvider()
    {
        $vectors = array (
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
