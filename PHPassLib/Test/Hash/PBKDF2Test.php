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
use PHPassLib\Hash\PBKDF2;

/**
 *
 */
class PBKDF2Test extends \PHPUnit_Framework_TestCase
{

    /**
     * @test
     */
    public function knownTestVectorsBehaveAsExpected()
    {
        $vectors = array (
            array ("password", '$pbkdf2$1212$OB.dtnSEXZK8U5cgxU/GYQ$y5LKPOplRmok7CZp/aqVDVg8zGI'),
            array ("password", '$pbkdf2-sha256$1212$4vjV83LKPjQzk31VI4E0Vw$hsYF68OiOUPdDZ1Fg.fJPeq1h/gXXY7acBp9/6c.tmQ'),
            array ("password", '$pbkdf2-sha512$1212$RHY0Fr3IDMSVO/RSZyb5ow$eNLfBK.eVozomMr.1gYa17k9B7KIK25NOEshvhrSX.esqY3s.FvWZViXz4KoLlQI.BzY/YTNJOiKc5gBYFYGww'),
        );

        foreach ($vectors as $vector) {
            $this->assertEquals(PBKDF2::hash($vector[0], $vector[1]), $vector[1]);
        }

        $this->assertEquals(PBKDF2::hash('', '$pbkdf2$01212$THDqatpidANpadlLeTeOEg$HV3oi1k5C5LQCgG1BMOL.BX4YZc'), '*0');

        $this->assertEquals(PBKDF2::hash('', '*0'), '*1');
        $this->assertEquals(PBKDF2::hash('', '*1'), '*0');
    }

    /**
     *
     */
    public function hashGeneratesAValidHashBasedOnInput()
    {
        $this->assertRegExp(
            '/^\$2a\$12\$[\.\/0-9A-Za-z]{53}$/',
            PBKDF2::hash('password'),
            strlen(PBKDF2::hash('password'))
        );
/*
        $this->assertEquals(
            '$2a$12$saltSALTsaltSALTsaltS.Nzx2lC23KwaadwZ/.FJSLXE9ledPIK6',
            PBKDF2::hash('password', array ('salt' => 'saltSALTsaltSALTsaltSA'))
        );

        $this->assertRegExp(
            '/^\$2y\$12\$[\.\/0-9A-Za-z]{53}$/',
            PBKDF2::hash('password', array ('ident' => '2y'))
        );

        $this->assertRegExp(
            '/^\$2a\$04\$[\.\/0-9A-Za-z]{53}$/',
            PBKDF2::hash('password', array ('rounds' => 4))
        );
*/
    }

    /**
     * @test
     */
    public function verifyProperlyVerifiesPasswordHashes()
    {
        $this->assertTrue(
            PBKDF2::verify('password', '$pbkdf2-sha256$6400$.6UI/S.nXIk8jcbdHx3Fhg$98jZicV16ODfEsEZeYPGHU3kbrUrvUEXOPimVSQDD44'),
            PBKDF2::hash('password', '$pbkdf2-sha256$6400$.6UI/S.nXIk8jcbdHx3Fhg$98jZicV16ODfEsEZeYPGHU3kbrUrvUEXOPimVSQDD44')
        );

        $this->assertFalse(
            PBKDF2::verify('wordpass', '$pbkdf2-sha256$6400$.6UI/S.nXIk8jcbdHx3Fhg$98jZicV16ODfEsEZeYPGHU3kbrUrvUEXOPimVSQDD44')
        );
    }

}