<?php
/**
 * PHP Password Library
 *
 * @package PHPassLib\Tests
 * @author Ryan Chouinard <rchouinard@gmail.com>
 * @copyright Copyright (c) 2012, Ryan Chouinard
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 * @version 3.0.0-dev
 */

namespace PHPassLib\Test\Hash;

use PHPassLib\Hash\SHA256Crypt;

/**
 * SHA-256 Crypt Module Tests
 *
 * @package PHPassLib\Tests
 * @author Ryan Chouinard <rchouinard@gmail.com>
 * @copyright Copyright (c) 2012, Ryan Chouinard
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 */
class SHA256CryptTest extends \PHPUnit_Framework_TestCase
{

    /**
     * Provide valid test vectors.
     *
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
     * Provide invalid test vectors.
     *
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
     * Verify that the class produces correct results with valid test vectors.
     *
     * @test
     * @dataProvider validTestVectorProvider
     * @param string $password
     * @param string $hash
     */
    public function validTestVectorsProduceExpectedResults($password, $hash)
    {
        $this->assertEquals($hash, SHA256Crypt::hash($password, $hash));
        $this->assertTrue(SHA256Crypt::verify($password, $hash));
    }

    /**
     * Verify that the class produces correct results with invalid test vectors.
     *
     * @test
     * @dataProvider invalidTestVectorProvider
     * @param string $password
     * @param string $hash
     */
    public function invalidTestVectorsProduceExpectedResults($password, $hash, $errorString)
    {
        $this->assertEquals($errorString, SHA256Crypt::hash($password, $hash));
        $this->assertFalse(SHA256Crypt::verify($password, $hash));
    }

    /**
     * @test
     */
    public function genconfigAndParseconfigProduceMatchingResults()
    {
        $options = array (
            'rounds' => 5000,
            'salt' => 'CCCCCCC.',
        );
        $config = SHA256Crypt::genConfig($options);

        $this->assertEquals('$5$CCCCCCC.', $config, $config);
        $this->assertSame($options, SHA256Crypt::parseConfig($config));

        $options = array (
            'rounds' => 8000,
            'salt' => 'CCCCCCC.',
        );
        $config = SHA256Crypt::genConfig($options);

        $this->assertEquals('$5$rounds=8000$CCCCCCC.', $config, $config);
        $this->assertSame($options, SHA256Crypt::parseConfig($config));
    }

}
