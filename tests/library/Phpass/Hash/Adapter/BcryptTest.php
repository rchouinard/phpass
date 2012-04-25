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
 * Bcrypt hash adapter tests
 *
 * @package PHPass\Tests
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
class BcryptTest extends \PHPUnit_Framework_TestCase
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
     * Run a number of standard test vectors through the adapter
     *
     * This tests the underlying crypt() method more than anything, but it's
     * a good idea to make sure the adapter doesn't inadvertently interfere.
     *
     * Case in point, I discovered a bug in crypt() because of these tests. :-)
     *
     * @test
     * @return void
     */
    public function testVectorsWorkAsExpected()
    {
        $adapter = $this->_adapter;

        $vectors = array (
            // John the Ripper 1.7.9
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

            // Openwall's crypt v1.2
            array ("U*U", '$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW'),
            array ("U*U*", '$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK'),
            array ("U*U*U", '$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a'),
            array ("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789chars after 72 are ignored", '$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui'),
            array ("\xa3", '$2x$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e'),
            array ("\xff\xff\xa3", '$2x$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e'),
            array ("\xff\xff\xa3", '$2y$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e'),
            array ("\xff\xff\xa3", '$2a$05$/OK.fbVrR/bpIqNJ5ianF.nqd1wy.pTMdcvrRWxyiGL2eMz.2a85.'),
            array ("\xa3", '$2y$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq'),
            array ("\xa3", '$2a$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq'),
            array ("1\xa3345", '$2x$05$/OK.fbVrR/bpIqNJ5ianF.o./n25XVfn6oAPaUvHe.Csk4zRfsYPi'),
            array ("\xff\xa3345", '$2x$05$/OK.fbVrR/bpIqNJ5ianF.o./n25XVfn6oAPaUvHe.Csk4zRfsYPi'),
            array ("\xff\xa334\xff\xff\xff\xa3345", '$2x$05$/OK.fbVrR/bpIqNJ5ianF.o./n25XVfn6oAPaUvHe.Csk4zRfsYPi'),
            array ("\xff\xa334\xff\xff\xff\xa3345", '$2y$05$/OK.fbVrR/bpIqNJ5ianF.o./n25XVfn6oAPaUvHe.Csk4zRfsYPi'),
            array ("\xff\xa334\xff\xff\xff\xa3345", '$2a$05$/OK.fbVrR/bpIqNJ5ianF.ZC1JEJ8Z4gPfpe1JOr/oyPXTWl9EFd.'),
            array ("\xff\xa3345", '$2y$05$/OK.fbVrR/bpIqNJ5ianF.nRht2l/HRhr6zmCp9vYUvvsqynflf9e'),
            array ("\xff\xa3345", '$2a$05$/OK.fbVrR/bpIqNJ5ianF.nRht2l/HRhr6zmCp9vYUvvsqynflf9e'),
            array ("\xa3ab", '$2a$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS'),
            array ("\xa3ab", '$2x$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS'),
            array ("\xa3ab", '$2y$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS'),
            array ("\xd1\x91", '$2x$05$6bNw2HLQYeqHYyBfLMsv/OiwqTymGIGzFsA4hOTWebfehXHNprcAS'),
            array ("\xd0\xc1\xd2\xcf\xcc\xd8", '$2x$05$6bNw2HLQYeqHYyBfLMsv/O9LIGgn8OMzuDoHfof8AQimSGfcSWxnS'),
            array ("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaachars after 72 are ignored as usual", '$2a$05$/OK.fbVrR/bpIqNJ5ianF.swQOIzjOiJ9GHEPuhEkvqrUyvWhEMx6'),
            array ("\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55", '$2a$05$/OK.fbVrR/bpIqNJ5ianF.R9xrDjiycxMbQE2bp.vgqlYpW5wx2yy'),
            array ("\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff", '$2a$05$/OK.fbVrR/bpIqNJ5ianF.9tQZzcJfm3uj2NvJ/n5xkhpqLrMpWCe'),
            array ("", '$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy'),
        );

        foreach ($vectors as $vector) {
            $this->assertEquals($adapter->crypt($vector[0], $vector[1]), $vector[1]);
        }

        // Invalid hashes from Openwall's crypt v1.2
        $this->assertEquals($adapter->crypt('', '$2a$03$CCCCCCCCCCCCCCCCCCCCC.'), '*0');
        $this->assertEquals($adapter->crypt('', '$2a$32$CCCCCCCCCCCCCCCCCCCCC.'), '*0');
        $this->assertEquals($adapter->crypt('', '$2z$05$CCCCCCCCCCCCCCCCCCCCC.'), '*0');

        // PHP's crypt actually fails the following tests, so the adapter
        // works around them.
        //
        // See https://bugs.php.net/bug.php?id=61852
        $this->assertEquals($adapter->crypt('', '$2`$05$CCCCCCCCCCCCCCCCCCCCC.'), '*0');
        $this->assertEquals($adapter->crypt('', '$2{$05$CCCCCCCCCCCCCCCCCCCCC.'), '*0');
        $this->assertEquals($adapter->crypt('', '*0'), '*1');
        $this->assertEquals($adapter->crypt('', '*1'), '*0');
    }

    /**
     * Test that setOptions() properly sets configuration options
     *
     * @test
     * @return void
     */
    public function setOptionMethodAffectsConfiguration()
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
        $this->assertRegExp('/^\$2[axy]{1}\$\d{2}\$[\.\/0-9A-Za-z]{22}$/', $salt);

        // Generates a valid hash string
        $hash = $adapter->crypt($password, $salt);
        $this->assertRegExp('/^\$2[axy]{1}\$\d{2}\$[\.\/0-9A-Za-z]{53}$/', $hash);
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