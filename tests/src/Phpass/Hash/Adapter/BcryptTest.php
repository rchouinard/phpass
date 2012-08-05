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
class BcryptTest extends TestCase
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
        $this->_adapter = new Bcrypt;
    }

    /**
     * @return array
     */
    public function validTestVectorProvider()
    {
        $vectors = array (
            // From John the Ripper 1.7.9
            array ("U*U", '$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW'),
            array ("U*U*", '$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK'),
            array ("U*U*U", '$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a'),
            array ("", '$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy'),
            array ("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789chars after 72 are ignored", '$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui'),
            array ("\xa3", '$2x$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e'),
            array ("\xa3", '$2y$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq'),
            array ("\xd1\x91", '$2x$05$6bNw2HLQYeqHYyBfLMsv/OiwqTymGIGzFsA4hOTWebfehXHNprcAS'),
            array ("\xd0\xc1\xd2\xcf\xcc\xd8", '$2x$05$6bNw2HLQYeqHYyBfLMsv/O9LIGgn8OMzuDoHfof8AQimSGfcSWxnS'),
            array ("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaachars after 72 are ignored as usual", '$2a$05$/OK.fbVrR/bpIqNJ5ianF.swQOIzjOiJ9GHEPuhEkvqrUyvWhEMx6'),
            array ("\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55", '$2a$05$/OK.fbVrR/bpIqNJ5ianF.R9xrDjiycxMbQE2bp.vgqlYpW5wx2yy'),
            array ("", '$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy'),
            array ("\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff", '$2a$05$/OK.fbVrR/bpIqNJ5ianF.9tQZzcJfm3uj2NvJ/n5xkhpqLrMpWCe'),
        );

        return $vectors;
    }

    /**
     * @return array
     */
    public function invalidTestVectorProvider()
    {
        $vectors = array (
            // From Openwall's crypt v1.2
            array ("", '$2a$03$CCCCCCCCCCCCCCCCCCCCC.', '*0'),
            array ("", '$2a$32$CCCCCCCCCCCCCCCCCCCCC.', '*0'),
            array ("", '$2z$05$CCCCCCCCCCCCCCCCCCCCC.', '*0'),

            // PHP's crypt actually fails the following tests, so the adapter
            // works around them.
            //
            // See https://bugs.php.net/bug.php?id=61852
            array ("", '$2`$05$CCCCCCCCCCCCCCCCCCCCC.', '*0'),
            array ("", '$2{$05$CCCCCCCCCCCCCCCCCCCCC.', '*0'),
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
        $config = substr($hash, 0, 29);
        $this->assertEquals($hash, $this->_adapter->crypt($password, $config));
    }

    /**
     * @test
     * @dataProvider invalidTestVectorProvider
     */
    public function invalidTestVectorsProduceExpectedResults($password, $hash, $errorString)
    {
        $config = substr($hash, 0, 29);
        $this->assertEquals($errorString, $this->_adapter->crypt($password, $config));
    }

    /**
     * @test
     * @return void
     */
    public function modifyingOptionsUpdatesAdapterBehavior()
    {
        $adapter = $this->_adapter;

        $adapter->setOptions(array ('identifier' => '2a', 'iterationCountLog2' => 5));
        $this->assertStringStartsWith('$2a$05$', $adapter->genSalt());

        $adapter->setOptions(array ('iterationCountLog2' => 8));
        $this->assertStringStartsWith('$2a$08$', $adapter->genSalt());

        $adapter->setOptions(array ('identifier' => '2x'));
        $this->assertStringStartsWith('$2x$08$', $adapter->genSalt());

        $adapter->setOptions(array ('identifier' => '2y'));
        $this->assertStringStartsWith('$2y$08$', $adapter->genSalt());

        try {
            $adapter->setOptions(array ('identifier' => 'invalid'));
        } catch (\Exception $e) {}
        $this->assertInstanceOf('Phpass\\Exception\\InvalidArgumentException', $e);
        unset($e);

        try {
            $adapter->setOptions(array ('iterationCountLog2' => '0'));
        } catch (\Exception $e) {}
        $this->assertInstanceOf('Phpass\\Exception\\InvalidArgumentException', $e);
        unset($e);
    }

}
