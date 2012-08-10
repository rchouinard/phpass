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

use PHPassLib\Hash\BSDiCrypt;

/**
 * BSDi / Extended DES Crypt Module Tests
 *
 * @package PHPassLib\Tests
 * @author Ryan Chouinard <rchouinard@gmail.com>
 * @copyright Copyright (c) 2012, Ryan Chouinard
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 */
class BSDiCryptTest extends \PHPUnit_Framework_TestCase
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
            array ("U*U*U*U*", '_J9..CCCCXBrJUJV154M'),
            array ("U*U***U", '_J9..CCCCXUhOBTXzaiE'),
            array ("U*U***U*", '_J9..CCCC4gQ.mB/PffM'),
            array ("*U*U*U*U", '_J9..XXXXvlzQGqpPPdk'),
            array ("*U*U*U*U*", '_J9..XXXXsqM/YSSP..Y'),
            array ("*U*U*U*U*U*U*U*U", '_J9..XXXXVL7qJCnku0I'),
            array ("*U*U*U*U*U*U*U*U*", '_J9..XXXXAj8cFbP5scI'),
            array ("ab1234567", '_J9..SDizh.vll5VED9g'),
            array ("cr1234567", '_J9..SDizRjWQ/zePPHc'),
            array ("zxyDPWgydbQjgq", '_J9..SDizxmRI1GjnQuE'),
            array ("726 even", '_K9..SaltNrQgIYUAeoY'),
            array ("", '_J9..SDSD5YGyRCr4W4c'),
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
            array ("", '_K1.!crsmZxOLzfJH8iw', '*0'),
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
        $config = substr($hash, 0, 9);
        $this->assertEquals($hash, BSDiCrypt::hash($password, $config));
        $this->assertTrue(BSDiCrypt::verify($password, $hash));
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
        $config = substr($hash, 0, 9);
        $this->assertEquals($errorString, BSDiCrypt::hash($password, $config));
        $this->assertFalse(BSDiCrypt::verify($password, $hash));
    }

    /**
     * @test
     */
    public function genconfigAndParseconfigProduceMatchingResults()
    {
        $options = array (
            'rounds' => 5001,
            'salt' => 'CCC.',
        );
        $config = BSDiCrypt::genConfig($options);

        $this->assertEquals('_7C/.CCC.', $config);
        $this->assertSame($options, BSDiCrypt::parseConfig($config));

        $options = array (
            'rounds' => 5000,
            'salt' => 'CCC.',
        );
        $config = BSDiCrypt::genConfig($options);
        $options['rounds'] = 4999; // Module subtracts 1 from even rounds
                                   // when generating the config string.

        $this->assertEquals('_5C/.CCC.', $config, $config);
        $this->assertSame($options, BSDiCrypt::parseConfig($config));
    }

}
