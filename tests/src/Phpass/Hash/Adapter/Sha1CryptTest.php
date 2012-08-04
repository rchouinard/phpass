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
 * SHA512 crypt hash adapter tests
 *
 * @package PHPass\Tests
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
class Sha1CryptTest extends \PHPUnit_Framework_TestCase
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
     * Run a number of standard test vectors through the adapter
     *
     * @test
     * @return void
     */
    public function knownTestVectorsBehaveAsExpected()
    {
        $adapter = $this->_adapter;

        $vectors = array (
            array ("password", '$sha1$40000$jtNX3nZ2$hBNaIXkt4wBI2o5rsi8KejSjNqIq'),
            array ("password", '$sha1$19703$iVdJqfSE$v4qYKl1zqYThwpjJAoKX6UvlHq/a'),
            array ("password", '$sha1$21773$uV7PTeux$I9oHnvwPZHMO0Nq6/WgyGV/tDJIH'),
            array ("test", '$sha1$1$Wq3GL2Vp$C8U25GvfHS8qGHimExLaiSFlGkAe'),
            //array ("", ''),
        );

        foreach ($vectors as $vector) {
            $this->assertEquals($vector[1], $adapter->crypt($vector[0], $vector[1]));
        }

        $this->assertEquals($adapter->crypt('', '*0'), '*1');
        $this->assertEquals($adapter->crypt('', '*1'), '*0');
    }

}