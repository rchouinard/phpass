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
namespace Phpass\Hash;
use Phpass\Hash\Base;

/**
 * @see PHPUnit_Framework_TestCase
 */
require_once 'PHPUnit/Framework/TestCase.php';

/**
 * @see Phpass\Hash\Base
 */
require_once 'Phpass/Hash/Base.php';

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
class BaseTest extends \PHPUnit_Framework_TestCase
{

    /**
     * (non-PHPdoc)
     * @see PHPUnit_Framework_TestCase::run()
     */
    public function run(\PHPUnit_Framework_TestResult $result = null)
    {
        $this->setPreserveGlobalState(false);
        return parent::run($result);
    }

    /**
     * @return array
     */
    public function providerForFactoryTest()
    {
        return array (
            array (
                'blowfish',
                'Phpass\Hash\Blowfish'
            ),
            array (
                'extdes',
                'Phpass\Hash\ExtDes'
            ),
            array (
                'pbkdf2',
                'Phpass\Hash\Pbkdf2'
            ),
            array (
                'portable',
                'Phpass\Hash\Portable'
            ),
            array (
                'Phpass\Hash\Blowfish',
                'Phpass\Hash\Blowfish'
            ),
            array (
                'Phpass\Hash\ExtDes',
                'Phpass\Hash\ExtDes'
            ),
            array (
                'Phpass\Hash\Pbkdf2',
                'Phpass\Hash\Pbkdf2'
            ),
            array (
                'Phpass\Hash\Portable',
                'Phpass\Hash\Portable'
            )
        );
    }

    /**
     * @test
     * @dataProvider providerForFactoryTest
     * @runInSeparateProcess
     * @param string $adapter
     * @param string $className
     * @return void
     */
    public function factoryMethodProperlyLoadsAdapter($adapter, $className)
    {
        if (method_exists($this, 'assertInstanceOf')) {
            $this->assertInstanceOf(
                $className, // Expected
                Base::factory($adapter) // Actual
            );
        } else {
            $this->assertType(
                $className, // Expected
                Base::factory($adapter) // Actual
            );
        }
    }

}