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
require_once 'Phpass.php';

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
class PhpassTest extends PHPUnit_Framework_TestCase
{

    /**
     * @return array
     */
    public function providerForConstructorOptions()
    {
        return array (
            array (
                array (
                    'adapter' => array (
                        'adapter' => 'blowfish',
                        'options' => array ()
                    )
                ),
                'Phpass_Adapter_Blowfish'
            ),
            array (
                array (
                    'adapter' => array (
                        'adapter' => 'extdes',
                        'options' => array ()
                    )
                ),
                'Phpass_Adapter_ExtDes'
            ),
            array (
                array (
                    'adapter' => array (
                        'adapter' => 'portable',
                        'options' => array ()
                    )
                ),
                'Phpass_Adapter_Portable'
            )
        );
    }

    /**
     * @test
     * @expectedException Phpass_Exception_MissingAdapter
     * @return void
     */
    public function constructorWithNoArgsSuppliesNoAdapter()
    {
        $phpass = new Phpass;
        $adapter = $phpass->getAdapter();
    }

    /**
     * @test
     * @dataProvider providerForConstructorOptions
     * @return void
     */
    public function constructorSetsProperAdapterFromOptions($options, $class)
    {
        $phpass = new Phpass($options);
        $adapter = $phpass->getAdapter();

        $this->assertType(
            $class, // Expected
            $adapter // Actual
        );
    }

}