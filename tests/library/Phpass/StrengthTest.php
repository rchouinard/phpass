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
namespace Phpass;

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
class StrengthTest extends \PHPUnit_Framework_TestCase
{

    /**
     * @test
     * @return void
     */
    public function defaultInstanceUsesNistAdapter()
    {
        $hash = new Strength;

        // Verify adapter instance
        $this->assertInstanceOf(
            'Phpass\\Strength\\Adapter\\Nist', // Expected
            $hash->getAdapter() // Actual
        );
    }

    /**
     * @test
     * @return void
     */
    public function passingAdapterViaConstructorCorrectlySetsInstance()
    {
        $adapter = new \Phpass\Strength\Adapter\Wolfram;
        $hash = new Strength($adapter);

        $this->assertInstanceOf(
            'Phpass\\Strength\\Adapter\\Wolfram', // Expected
            $hash->getAdapter() // Actual
        );
    }

    /**
     * @test
     * @return void
     */
    public function passingOptionsViaConstructorCorrectlySetsProperties()
    {
        $hash = new Strength(array (
            'adapter' => new \Phpass\Strength\Adapter\Nist
        ));

        $this->assertInstanceOf(
            'Phpass\\Strength\\Adapter\\Nist', // Expected
            $hash->getAdapter() // Actual
        );
    }

}