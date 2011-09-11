<?php
/**
 * Portable PHP password hashing framework.
 *
 * @package PHPass
 * @subpackage Tests
 * @category Cryptography
 * @author Solar Designer <solar at openwall.com>
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license Public Domain
 * @link http://www.openwall.com/phpass/ Original phpass project page.
 * @version 0.5
 */

require_once 'PHPUnit/Framework/TestCase.php';
require_once 'Phpass/Adapter/Base.php';

/**
 * Portable PHP password hashing framework.
 *
 * @package PHPass
 * @subpackage Tests
 * @category Cryptography
 * @author Solar Designer <solar at openwall.com>
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license Public Domain
 * @link http://www.openwall.com/phpass/ Original phpass project page.
 * @version 0.5
 */
class Phpass_AdapterTest extends PHPUnit_Framework_TestCase
{

    /**
     * @return array
     */
    public function adapterNameProviderForFactoryTest()
    {
        return array (
            array (
                '\Phpass\Adapter\Blowfish',
                '\Phpass\Adapter\Blowfish'
            ),
            array (
                '\Phpass\Adapter\ExtDes',
                '\Phpass\Adapter\ExtDes'
            ),
            array (
                '\Phpass\Adapter\Portable',
                '\Phpass\Adapter\Portable'
            ),
            array (
                'blowfish',
                '\Phpass\Adapter\Blowfish'
            ),
            array (
                'extdes',
                '\Phpass\Adapter\ExtDes'
            ),
            array (
                'portable',
                '\Phpass\Adapter\Portable'
            ),
            /*array (
                '$2a$08$',
                '\Phpass\Adapter\Blowfish'
            ),
            array (
                '_',
                '\Phpass\Adapter\ExtDes'
            ),
            array (
                '$P$',
                '\Phpass\Adapter\Portable'
            ),
            array (
                '$H$',
                '\Phpass\Adapter\Portable'
            )*/
        );
    }

    /**
     * @test
     * @dataProvider adapterNameProviderForFactoryTest
     * @param string $adapter
     * @param string $className
     */
    public function factoryMethodShouldLoadAdapter($adapter, $className)
    {
        $this->assertType(
            $className, // Expected
            \Phpass\Adapter\Base::factory($adapter), // Actual
            "Factory method should load ${className}"
        );
    }

}