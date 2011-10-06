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
 * @see PHPUnit_Framework_TestCase
 */
require_once 'PHPUnit/Framework/TestCase.php';

/**
 * @see Phpass
 */
require_once 'Phpass.php';

/**
 * @see Phpass\Adapter\Blowfish
 */
require_once 'Phpass/Adapter/Blowfish.php';

/**
 * @see Phpass\Adapter\ExtDes
 */
require_once 'Phpass/Adapter/ExtDes.php';

/**
 * @see Phpass\Adapter\Portable
 */
require_once 'Phpass/Adapter/Portable.php';

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
class PhpassTest extends PHPUnit_Framework_TestCase
{

    /**
     * @test
     * @return void
     */
    public function noConstructorArgsDefaultsToBlowfishAdapter()
    {
        $phpass = new Phpass;
        $adapter = $phpass->getAdapter();

        $this->assertInstanceOf(
            'Phpass\Adapter\Blowfish',
            $adapter
        );
    }

    /**
     * @test
     * @return void
     */
    public function passingAdapterNameToConstructorDefaultsToThatAdapter()
    {
        $phpass = new Phpass('extdes');
        $adapter = $phpass->getAdapter();

        $this->assertInstanceOf(
            'Phpass\Adapter\ExtDes',
            $adapter
        );
    }

    /**
     * @test
     * @return void
     */
    public function passingAdapterInstanceToConstructorDefaultsToThatAdapter()
    {
        $phpass = new Phpass(new Phpass\Adapter\ExtDes);
        $adapter = $phpass->getAdapter();

        $this->assertInstanceOf(
            'Phpass\Adapter\ExtDes',
            $adapter
        );
    }

    /**
     * @test
     * @return void
     */
    public function hashesAreProperlyVerified()
    {
        $phpass = new Phpass;

        $this->assertTrue(
            $phpass->checkPassword('password', $phpass->hashPassword('password'))
        );

        $this->assertFalse(
            $phpass->checkPassword('password', $phpass->hashPassword('wordpass'))
        );
    }

}