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

/**
 * @namespace
 */
namespace Phpass\Hash\Adapter;

/**
 * PHPass portable hash adapter tests
 *
 * @package PHPass\Tests
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
class PortableTest extends \PHPUnit_Framework_TestCase
{

    /**
     * @var Phpass\Hash\Adapter
     */
    protected $_adapter;

    /**
     * (non-PHPdoc)
     * @see PHPUnit_Framework_TestCase::setUp()
     */
    protected function setUp()
    {
        $this->_adapter = new Portable;
    }

    /**
     * Run a number of standard test vectors through the adapter
     *
     * @test
     * @return void
     */
    public function knownTestVectorsBehaveAsExpected()
    {
        $adapter = $this->_adapter;

        $vectors = array (
            // Generated using Openwall's PasswordHash class
            array ("U*U", '$P$8Y50qr/rEJ5LQ0ni8R9WUYUE70TDSu/'),
            array ("U*U*", '$P$8/LEV9JjUM.FMZ6nsACmgyBkaeD4Ka1'),
            array ("U*U*U", '$P$8S7UaSkpWYULBOjfjdL7oWoL6bPjrZ/'),
            array ("", '$P$876GykTPTcUNTbMmjOdVvPrCEM/.W80'),
            array ("", '$P$8CCCCCCCCprnqtTraJ2.nIjE4ET2Mh/'),
        );

        foreach ($vectors as $vector) {
            $this->assertEquals($adapter->crypt($vector[0], $vector[1]), $vector[1]);
        }

        // Invalid salts
        $this->assertEquals($adapter->crypt('', '$P$4CCCCCCCC'), '*0');
        $this->assertEquals($adapter->crypt('', '$P$TCCCCCCCC'), '*0');
        $this->assertEquals($adapter->crypt('', '$X$8CCCCCCCC'), '*0');

        // Invalid hashes
        $this->assertEquals($adapter->crypt('', '$P$8CCCCCCCCprnqtTraJ2!nIjE4ET2Mh/'), '*0');
        $this->assertEquals($adapter->crypt('', '$P{8CCCCCCCCprnqtTraJ2.nIjE4ET2Mh/'), '*0');
        $this->assertEquals($adapter->crypt('', '*0'), '*1');
        $this->assertEquals($adapter->crypt('', '*1'), '*0');
    }

    /**
     * Test that setOptions() properly sets configuration options
     *
     * @test
     * @return void
     */
    public function modifyingOptionsUpdatesAdapterBehavior()
    {
        $adapter = $this->_adapter;

        $adapter->setOptions(array ('iterationCountLog2' => 7));
        $this->assertStringStartsWith('$P$A', $adapter->genSalt());

        $adapter->setOptions(array ('phpBBCompat' => true));
        $this->assertStringStartsWith('$H$A', $adapter->genSalt());

        $adapter->setOptions(array ('iterationCountLog2' => 10, 'phpBBCompat' => false));
        $this->assertStringStartsWith('$P$D', $adapter->genSalt());

        try {
            $adapter->setOptions(array ('iterationCountLog2' => 6));
        } catch (\Exception $e) {}
        $this->assertInstanceOf('Phpass\\Exception\\InvalidArgumentException', $e);
        unset($e);

        try {
            $adapter->setOptions(array ('iterationCountLog2' => 31));
        } catch (\Exception $e) {}
        $this->assertInstanceOf('Phpass\\Exception\\InvalidArgumentException', $e);
        unset($e);
    }

    /**
     * Test that the adapter generates a valid hash
     *
     * @test
     * @return void
     */
    public function adapterGeneratesValidHashString()
    {
        $adapter = $this->_adapter;
        $password = 'password';

        // Generates a valid salt string
        $salt = $adapter->genSalt();
        $this->assertRegExp('/^\$[PH]{1}\$[\.\/0-9A-Za-z]{9}$/', $salt);

        // Generates a valid hash string
        $hash = $adapter->crypt($password, $salt);
        $this->assertRegExp('/^\$[PH]{1}\$[\.\/0-9A-Za-z]{31}$/', $hash);
    }

    /**
     * Test that the adapter generates the same hash given the same input
     *
     * @test
     * @return void
     */
    public function adapterConsistentlyGeneratesHashStrings()
    {
        $adapter = $this->_adapter;
        $password = 'password';

        $salt = $adapter->genSalt();
        $hash = $adapter->crypt($password, $salt);

        // Generates the same hash for the password given the stored salt
        $this->assertEquals($hash, $adapter->crypt($password, $salt));

        // Generates the same hash for the password given the stored hash
        $this->assertEquals($hash, $adapter->crypt($password, $hash));
    }

}