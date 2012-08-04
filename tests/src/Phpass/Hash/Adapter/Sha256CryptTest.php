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
 * SHA256 crypt hash adapter tests
 *
 * @package PHPass\Tests
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
class Sha256CryptTest extends \PHPUnit_Framework_TestCase
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
        $this->_adapter = new Sha256Crypt;
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
            // http://www.akkadia.org/drepper/SHA-crypt.txt
            array ("Hello world!", '$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5'),
            array ("Hello world!", '$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA'),
            array ("This is just a test", '$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5'),
            array ("a very much longer text to encrypt.  This one even stretches over morethan one line.", '$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1'),
            array ("we have a short salt string but not a short password", '$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/'),
            array ("a short string", '$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD'),
            array ("the minimum number is still observed", '$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC'),
            //array ("", ''),
        );

        foreach ($vectors as $vector) {
            $this->assertEquals($adapter->crypt($vector[0], $vector[1]), $vector[1]);
        }

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

        $adapter->setOptions(array ('iterationCount' => 10000));
        $this->assertStringStartsWith('$5$rounds=10000', $adapter->genSalt());

        $adapter->setOptions(array ('iterationCount' => 25000));
        $this->assertStringStartsWith('$5$rounds=25000', $adapter->genSalt());

        $adapter->setOptions(array ('iterationCount' => 5000));
        $this->assertStringStartsWith('$5$', $salt = $adapter->genSalt());
        $this->assertStringStartsNotWith('$5$rounds=', $salt);
        unset ($salt);

        $adapter->setOptions(array ('iterationCountLog2' => 18));
        $this->assertStringStartsWith('$5$rounds=262144', $adapter->genSalt());

        try {
            $adapter->setOptions(array ('iterationCount' => 999));
        } catch (\Exception $e) {}
        $this->assertInstanceOf('Phpass\\Exception\\InvalidArgumentException', $e);
        unset($e);

        try {
            $adapter->setOptions(array ('iterationCount' => 1000000));
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
        $this->assertRegExp('/^\$5\$(?:rounds=\d{4,9}\$)?[\.\/0-9A-Za-z]{0,16}\$?$/', $salt);

        // Generates a valid hash string
        $hash = $adapter->crypt($password, $salt);
        $this->assertRegExp('/^\$5\$(?:rounds=\d{4,9}\$)?[\.\/0-9A-Za-z]{0,16}\$?[\.\/0-9A-Za-z]{43}$/', $hash);
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