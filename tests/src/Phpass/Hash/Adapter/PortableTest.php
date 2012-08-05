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
class PortableTest extends TestCase
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
        $config = substr($hash, 0, 12);
        $this->assertEquals($hash, $this->_adapter->crypt($password, $config));
    }

    /**
     * @test
     * @dataProvider invalidTestVectorProvider
     */
    public function invalidTestVectorsProduceExpectedResults($password, $hash, $errorString)
    {
        $config = substr($hash, 0, 12);
        $this->assertEquals($errorString, $this->_adapter->crypt($password, $config));
    }

}
