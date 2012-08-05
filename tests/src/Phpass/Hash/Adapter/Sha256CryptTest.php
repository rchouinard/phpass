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

namespace Phpass\Hash\Adapter;

use \PHPUnit_Framework_TestCase as TestCase;

/**
 * PHP Password Library
 *
 * @package PHPass\Tests
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
class Sha256CryptTest extends TestCase
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
     * @return array
     */
    public function validTestVectorProvider()
    {
        $vectors = array (
                // http://www.akkadia.org/drepper/SHA-crypt.txt
                array ("Hello world!", '$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5'),
                array ("Hello world!", '$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA'),
                array ("This is just a test", '$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5'),
                array ("a very much longer text to encrypt.  This one even stretches over morethan one line.", '$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1'),
                array ("we have a short salt string but not a short password", '$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/'),
                array ("a short string", '$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD'),
                array ("the minimum number is still observed", '$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC'),
        );

        return $vectors;
    }

    /**
     * @return array
     */
    public function invalidTestVectorProvider()
    {
        $vectors = array (
                array ("", '*0', '*1'),
                array ("", '*1', '*0'),
        );

        return $vectors;
    }

    /**
     * @test
     * @dataProvider validTestVectorProvider
     */
    public function validTestVectorsProduceExpectedResults($password, $hash)
    {
        $this->assertEquals($hash, $this->_adapter->crypt($password, $hash));
    }

    /**
     * @test
     * @dataProvider invalidTestVectorProvider
     */
    public function invalidTestVectorsProduceExpectedResults($password, $hash, $errorString)
    {
        $this->assertEquals($errorString, $this->_adapter->crypt($password, $hash));
    }

}
