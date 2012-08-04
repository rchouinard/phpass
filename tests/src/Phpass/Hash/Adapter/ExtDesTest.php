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
 * Extended DES hash adapter tests
 *
 * @package PHPass\Tests
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
class ExtDesTest extends \PHPUnit_Framework_TestCase
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
        $this->_adapter = new ExtDes;
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
            array ("U*U", '_zzD.2.nIWzugGxYyy0g'),
            array ("U*U*", '_zzD.TraJm.5udFKSqzI'),
            array ("U*U*U", '_zzD.CEM/afcFK40/mw.'),
            array ("", '_zzD.qtTr73yMBXbDqiI'),
            array ("", '_zzD.CCCCBeguG7nmIew'),
        );

        foreach ($vectors as $vector) {
            $this->assertEquals($adapter->crypt($vector[0], $vector[1]), $vector[1]);
        }

        // Invalid hashes
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

        // genSalt() will change 100000 to 99999 because it's even
        $adapter->setOptions(array ('iterationCount' => 100000));
        $this->assertStringStartsWith('_TOM.', $adapter->genSalt());

        // genSalt() will use 1234567 as-is, since it's already odd
        $adapter->setOptions(array ('iterationCount' => 1234567));
        $this->assertStringStartsWith('_5Oh2', $adapter->genSalt());

        // 2^16 => 65536 => 65535
        $adapter->setOptions(array ('iterationCountLog2' => 16));
        $this->assertStringStartsWith('_zzD.', $adapter->genSalt());

        try {
            $adapter->setOptions(array ('iterationCount' => 0));
        } catch (\Exception $e) {}
        $this->assertInstanceOf('Phpass\\Exception\\InvalidArgumentException', $e);
        unset($e);

        try {
            $adapter->setOptions(array ('iterationCount' => 16777216));
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
        $this->assertRegExp('/^_[\.\/0-9A-Za-z]{8}$/', $salt);

        // Generates a valid hash string
        $hash = $adapter->crypt($password, $salt);
        $this->assertRegExp('/^_[\.\/0-9A-Za-z]{19}$/', $hash);
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