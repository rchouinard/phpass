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

use PHPassLib\Hash\MD5Crypt;

/**
 * MD5 Crypt Module Tests
 *
 * @package PHPassLib\Tests
 * @author Ryan Chouinard <rchouinard@gmail.com>
 * @copyright Copyright (c) 2012, Ryan Chouinard
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 */
class MD5CryptTest extends \PHPUnit_Framework_TestCase
{

    /**
     * Provide valid test vectors.
     *
     * @return array
     */
    public function validTestVectorProvider()
    {
        $vectors = array (
            // From John the Ripper 1.7.9
            array ("0123456789ABCDE", '$1$12345678$aIccj83HRDBo6ux1bVx7D1'),
            array ("12345678", '$1$12345678$f8QoJuo0DpBRfQSD0vglc1'),
            array ("", '$1$$qRPK7m23GJusamGpoGLby/'),
            array ("no salt", '$1$$AuJCr07mI7DSew03TmBIv/'),
            array ("", '$1$12345678$xek.CpjQUVgdf/P2N9KQf/'),
            array ("1234", '$1$1234$BdIMOAWFOV2AQlLsrN/Sw.'),
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
        // TODO: Find a good source of test vectors
        $vectors = array (
            array ("invalid salt", '$1$`!@#%^&*$E6hD76/pKTS8qToBCkux30', '*0'),
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
        $this->assertEquals($hash, MD5Crypt::hash($password, $hash));
        $this->assertTrue(MD5Crypt::verify($password, $hash));
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
        $this->assertEquals($errorString, MD5Crypt::hash($password, $hash));
        $this->assertFalse(MD5Crypt::verify($password, $hash));
    }

    /**
     * @test
     */
    public function genconfigAndParseconfigProduceMatchingResults()
    {
        $options = array (
            'salt' => 'CCCCC.',
        );
        $config = MD5Crypt::genConfig($options);

        $this->assertEquals('$1$CCCCC.', $config);
        $this->assertSame($options, MD5Crypt::parseConfig($config));
    }

}
