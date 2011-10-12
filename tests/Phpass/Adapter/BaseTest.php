<?php
/**
 * Portable PHP password hashing framework.
 *
 * @package PHPass
 * @subpackage Tests
 * @category Cryptography
 * @author Solar Designer <solar at openwall.com>
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link http://www.openwall.com/phpass/ Original phpass project page.
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */

/**
 * @namespace
 */
namespace Phpass\Adapter;
use Phpass\Adapter\Base;

/**
 * @see PHPUnit_Framework_TestCase
 */
require_once 'PHPUnit/Framework/TestCase.php';

/**
 * @see Phpass\Adapter\Base
 */
require_once 'Phpass/Adapter/Base.php';

/**
 * Portable PHP password hashing framework.
 *
 * @package PHPass
 * @subpackage Tests
 * @category Cryptography
 * @author Solar Designer <solar at openwall.com>
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link http://www.openwall.com/phpass/ Original phpass project page.
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
                'Phpass\Adapter\Blowfish'
            ),
            array (
                'extdes',
                'Phpass\Adapter\ExtDes'
            ),
            array (
                'pbkdf2',
                'Phpass\Adapter\Pbkdf2'
            ),
            array (
                'portable',
                'Phpass\Adapter\Portable'
            ),
            array (
                'Phpass\Adapter\Blowfish',
                'Phpass\Adapter\Blowfish'
            ),
            array (
                'Phpass\Adapter\ExtDes',
                'Phpass\Adapter\ExtDes'
            ),
            array (
                'Phpass\Adapter\Pbkdf2',
                'Phpass\Adapter\Pbkdf2'
            ),
            array (
                'Phpass\Adapter\Portable',
                'Phpass\Adapter\Portable'
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
