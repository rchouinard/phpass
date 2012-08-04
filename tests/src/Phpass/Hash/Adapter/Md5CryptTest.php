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
 * MD5 crypt hash adapter tests
 *
 * @package PHPass\Tests
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
class Md5CryptTest extends \PHPUnit_Framework_TestCase
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
        $this->_adapter = new Md5Crypt;
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

        // TODO: Find a good source of test vectors
        $vectors = array (
        );

        foreach ($vectors as $vector) {
            $this->assertEquals($adapter->crypt($vector[0], $vector[1]), $vector[1]);
        }

        $this->assertEquals($adapter->crypt('', '*0'), '*1');
        $this->assertEquals($adapter->crypt('', '*1'), '*0');
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
        $this->assertRegExp('/^\$1\$[\.\/0-9A-Za-z]{0,8}\$?$/', $salt);

        // Generates a valid hash string
        $hash = $adapter->crypt($password, $salt);
        $this->assertRegExp('/^\$1\$[\.\/0-9A-Za-z]{0,8}\$?[\.\/0-9A-Za-z]{22}$/', $hash);
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