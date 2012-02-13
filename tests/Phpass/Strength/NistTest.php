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
 * @see Phpass\Strength\Nist
 */
require_once 'Phpass/Strength/Nist.php';

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
class NistTest extends \PHPUnit_Framework_TestCase
{

    /**
     * @test
     */
    public function checkMethodCalculatesExpectedResult()
    {
        $adapter = new Nist;
        $this->assertEquals( 0, $adapter->check(''));
        $this->assertEquals( 4, $adapter->check('M'));
        $this->assertEquals( 6, $adapter->check('My'));
        $this->assertEquals(18, $adapter->check('MySuperS'));
        $this->assertEquals(36, $adapter->check('MySuperSecretPasswor'));
        $this->assertEquals(37, $adapter->check('MySuperSecretPassword'));
        $this->assertEquals(43, $adapter->check('Super!Secret*Password'));
    }

}