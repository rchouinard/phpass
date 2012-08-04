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
namespace Phpass\Strength\Adapter;

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
     * @return array
     */
    public function passwordScoreProvider()
    {
        return array (
            array ('', 0),
            array ('MySuperSecretPassword', 78),
            array ('MySup3rS3cr3tP4ssw0rd', 155),
            array ('Super!Secret*Password', 119),
            array ('password32PASSWORD23password32PASSWORD23', 236),
            array ('123456', 8),
            array ('abcdef', 0)
        );
    }

    /**
     * @test
     * @dataProvider passwordScoreProvider
     * @param string $password
     * @param integer $expectedScore
     * @return void
     */
    public function checkMethodCalculatesExpectedResult($password, $expectedScore)
    {
        $adapter = new Wolfram;
        $this->assertEquals($expectedScore, $adapter->check($password));
    }

}