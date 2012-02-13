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
namespace Phpass\Strength;

/**
 * @see PHPUnit_Framework_TestCase
 */
require_once 'PHPUnit/Framework/TestCase.php';

/**
 * @see Phpass\Strength\Wolfram
 */
require_once 'Phpass/Strength/Wolfram.php';

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
class WolframTest extends \PHPUnit_Framework_TestCase
{

    /**
     * @test
     */
    public function checkMethodCalculatesExpectedResult()
    {
        $adapter = new Wolfram;
        $this->assertEquals(  0, $adapter->check(''));
        $this->assertEquals( 78, $adapter->check('MySuperSecretPassword'));
        $this->assertEquals(155, $adapter->check('MySup3rS3cr3tP4ssw0rd'));
        $this->assertEquals(115, $adapter->check('Super!Secret*Password'));
    }

}