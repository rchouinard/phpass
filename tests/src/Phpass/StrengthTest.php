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

namespace Phpass;

use \PHPUnit_Framework_TestCase as TestCase;
use Phpass\Strength\Adapter\Wolfram;

/**
 * PHP Password Library
 *
 * @package PHPass\Tests
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
            'Phpass\\Strength\\Adapter\\Nist', // Expected
            $hash->getAdapter() // Actual
        );
    }

    /**
     * @test
     */
    public function passingAdapterViaConstructorCorrectlySetsInstance()
    {
        $hash = new Strength(new Wolfram);
        $this->assertInstanceOf(
            'Phpass\\Strength\\Adapter\\Wolfram', // Expected
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
            'Phpass\\Strength\\Adapter\\Wolfram', // Expected
            $hash->getAdapter() // Actual
        );
    }

}
