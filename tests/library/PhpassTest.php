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
 * @version 0.5
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
                        'type' => 'blowfish',
                        'options' => array ()
                    )
                ),
                '\Phpass\Adapter\Blowfish'
            ),
            array (
                array (
                    'adapter' => array (
                        'type' => 'extdes',
                        'options' => array ()
                    )
                ),
                '\Phpass\Adapter\ExtDes'
            ),
            array (
                array (
                    'adapter' => array (
                        'type' => 'portable',
                        'options' => array ()
                    )
                ),
                '\Phpass\Adapter\Portable'
            )
        );
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