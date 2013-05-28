<?php
/**
 * PHP Password Library
 *
 * @package PHPassLib\Tests
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */

namespace PHPassLib;

use \PHPUnit_Framework_TestCase as TestCase;
use PHPassLib\Strength\Adapter\Wolfram;

/**
 * PHP Password Library
 *
 * @package PHPassLib\Tests
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
class StrengthTest extends TestCase
{

    /**
     * @test
     */
    public function defaultInstanceUsesNistAdapter()
    {
        $hash = new Strength;
        $this->assertInstanceOf(
            'PHPassLib\\Strength\\Adapter\\Nist', // Expected
            $hash->getAdapter() // Actual
        );
    }

    /**
     * @test
     */
    public function passingAdapterViaConstructorCorrectlySetsInstance()
    {
        $hash = new Strength(new \PHPassLib\Strength\Adapter\Wolfram);
        $this->assertInstanceOf(
            'PHPassLib\\Strength\\Adapter\\Wolfram', // Expected
            $hash->getAdapter() // Actual
        );
    }

    /**
     * @test
     */
    public function passingOptionsViaConstructorCorrectlySetsProperties()
    {
        $hash = new Strength(array (
            'adapter' => new Wolfram,
        ));

        $this->assertInstanceOf(
            'PHPassLib\\Strength\\Adapter\\Wolfram', // Expected
            $hash->getAdapter() // Actual
        );
    }

}
