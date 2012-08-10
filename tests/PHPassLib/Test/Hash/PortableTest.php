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

use PHPassLib\Hash\Portable;

/**
 * PHPass Portable Module Tests
 *
 * @package PHPassLib\Tests
 * @author Ryan Chouinard <rchouinard@gmail.com>
 * @copyright Copyright (c) 2012, Ryan Chouinard
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 */
class PortableTest extends \PHPUnit_Framework_TestCase
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
            array ("test1", '$H$9aaaaaSXBjgypwqm.JsMssPLiS8YQ00'),
            array ("123456", '$H$9PE8jEklgZhgLmZl5.HYJAzfGCQtzi1'),
            array ("123456", '$H$9pdx7dbOW3Nnt32sikrjAxYFjX8XoK1'),
            array ("thisisalongertestPW", '$P$912345678LIjjb6PhecupozNBmDndU0'),
            array ("JohnRipper", '$P$612345678si5M0DDyPpmRCmcltU/YW/'),
            array ("JohnRipper", '$H$712345678WhEyvy1YWzT4647jzeOmo0'),
            array ("JohnRipper", '$P$B12345678L6Lpt4BxNotVIMILOa9u81'),
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
        $config = substr($hash, 0, 12);
        $this->assertEquals($hash, Portable::hash($password, $config));
        $this->assertTrue(Portable::verify($password, $hash));
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
        $config = substr($hash, 0, 12);
        $this->assertEquals($errorString, Portable::hash($password, $config));
        $this->assertFalse(Portable::verify($password, $hash));
    }

    /**
     * @test
     */
    public function genconfigAndParseconfigProduceMatchingResults()
    {
        $options = array (
            'ident' => 'H',
            'rounds' => 15,
            'salt' => 'CCCCCCC.',
        );
        $config = Portable::genConfig($options);

        $this->assertEquals('$H$DCCCCCCC.', $config, $config);
        $this->assertSame($options, Portable::parseConfig($config));
    }

}
