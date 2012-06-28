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
use PHPassLib\Hash\BCrypt;

/**
 *
 */
class BCryptTest extends \PHPUnit_Framework_TestCase
{

    /**
     * @test
     */
    public function knownTestVectorsBehaveAsExpected()
    {
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
            $this->assertEquals(BCrypt::hash($vector[0], $vector[1]), $vector[1]);
        }

        // Invalid hashes from Openwall's crypt v1.2
        $this->assertEquals(BCrypt::hash('', '$2a$03$CCCCCCCCCCCCCCCCCCCCC.'), '*0');
        $this->assertEquals(BCrypt::hash('', '$2a$32$CCCCCCCCCCCCCCCCCCCCC.'), '*0');
        $this->assertEquals(BCrypt::hash('', '$2z$05$CCCCCCCCCCCCCCCCCCCCC.'), '*0');

        // PHP's crypt actually fails the following tests, so the adapter
        // works around them.
        //
        // See https://bugs.php.net/bug.php?id=61852
        $this->assertEquals(BCrypt::hash('', '$2`$05$CCCCCCCCCCCCCCCCCCCCC.'), '*0');
        $this->assertEquals(BCrypt::hash('', '$2{$05$CCCCCCCCCCCCCCCCCCCCC.'), '*0');
        $this->assertEquals(BCrypt::hash('', '*0'), '*1');
        $this->assertEquals(BCrypt::hash('', '*1'), '*0');
    }

    /**
     * @test
     */
    public function hashGeneratesAValidHashBasedOnInput()
    {
        $this->assertRegExp(
            '/^\$2a\$12\$[\.\/0-9A-Za-z]{53}$/',
            BCrypt::hash('password')
        );

        $this->assertEquals(
            '$2a$12$saltSALTsaltSALTsaltS.Nzx2lC23KwaadwZ/.FJSLXE9ledPIK6',
            BCrypt::hash('password', array ('salt' => 'saltSALTsaltSALTsaltSA'))
        );

        $this->assertRegExp(
            '/^\$2y\$12\$[\.\/0-9A-Za-z]{53}$/',
            BCrypt::hash('password', array ('ident' => '2y'))
        );

        $this->assertRegExp(
            '/^\$2a\$04\$[\.\/0-9A-Za-z]{53}$/',
            BCrypt::hash('password', array ('rounds' => 4))
        );
    }

    /**
     * @test
     */
    public function verifyProperlyVerifiesPasswordHashes()
    {
        $this->assertTrue(
            BCrypt::verify('password', '$2a$12$saltSALTsaltSALTsaltS.Nzx2lC23KwaadwZ/.FJSLXE9ledPIK6')
        );

        $this->assertFalse(
            BCrypt::verify('wordpass', '$2a$12$saltSALTsaltSALTsaltS.Nzx2lC23KwaadwZ/.FJSLXE9ledPIK6')
        );
    }

}