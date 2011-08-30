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
 * @version 0.4
 */

require_once 'PHPUnit/Framework/TestCase.php';
require_once 'Phpass/Adapter.php';

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
 * @version 0.4
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
                'Phpass_Adapter_Blowfish',
                'Phpass_Adapter_Blowfish'
            ),
            array (
                'Phpass_Adapter_ExtDes',
                'Phpass_Adapter_ExtDes'
            ),
            array (
                'Phpass_Adapter_Portable',
                'Phpass_Adapter_Portable'
            ),
            array (
                'blowfish',
                'Phpass_Adapter_Blowfish'
            ),
            array (
                'extdes',
                'Phpass_Adapter_ExtDes'
            ),
            array (
                'portable',
                'Phpass_Adapter_Portable'
            ),
            array (
                '$2a$08$',
                'Phpass_Adapter_Blowfish'
            ),
            array (
                '_',
                'Phpass_Adapter_ExtDes'
            ),
            array (
                '$P$',
                'Phpass_Adapter_Portable'
            ),
            array (
                '$H$',
                'Phpass_Adapter_Portable'
            )
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
        //try {
            $this->assertType(
                $className, // Expected
                Phpass_Adapter::factory($adapter), // Actual
                "Factory method should load ${className}"
            );
        //} catch (Exception $e) {
        //}
    }

}