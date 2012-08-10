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

namespace PHPassLib\Test\Application;

use PHPassLib\Application\Context;
use PHPassLib\Exception\RuntimeException;

/**
 * Application Context Tests
 *
 * @package PHPassLib\Tests
 * @author Ryan Chouinard <rchouinard@gmail.com>
 * @copyright Copyright (c) 2012, Ryan Chouinard
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 */
class ContextTest extends \PHPUnit_Framework_TestCase
{

    /**
     * @test
     */
    public function contextCanVerifyMultipleConfigurations()
    {
        $context = new Context;
        $context->addConfig('bcrypt');
        $context->addConfig('pbkdf2');

        $this->assertTrue($context->verify('password', '$2a$12$m8BI4QL9ALnhIspk70ZQ..xiSX2CHw2r0IZB4EAmV59vJ/1NOQNoy'));
        $this->assertTrue($context->verify('password', '$pbkdf2$12000$VOK/VpoqrPyLwl256fbq9A$GMLWbZHcx1cSeKv8vqMkro424T4'));

        $exception = null;
        try {
            $context->verify('password', '$1$Gwzk6VAb$0b.FnV/z3WV7JsdT0JUMT1');
        } catch (RuntimeException $exception) {
        }

        $this->assertInstanceOf('PHPassLib\\Exception', $exception);
    }

    /**
     * @test
     */
    public function contextUsesFirstConfigForHashing()
    {
        $context = new Context;
        $context->addConfig('bcrypt');
        $context->addConfig('pbkdf2');

        $this->assertStringStartsWith('$2a$', $context->hash('password'));
    }

    /**
     * @test
     */
    public function contextIdentifiesOutdatedHashes()
    {
        $context = new Context;
        $context->addConfig('pbkdf2', array ('digest' => 'sha1'));
        $context->addConfig('bcrypt');

        $this->assertFalse($context->needsUpdate('$pbkdf2$12000$3XWNbVbeGaE/6PD2D/fPMA$5ePab2Y6zuxk.grl5Yo/QvgNrlY'));
        $this->assertTrue($context->needsUpdate('$pbkdf2$10000$27ERFDenq28ObTH/QcxsAw$YIU6k8STkdoJ5qE2L47TaTYistA'));
        $this->assertTrue($context->needsUpdate('$2a$12$TeRU2URC/eV2z3qVoViiR.kYSqjQ4pMgOqycTSANspO.6IN8TNOHq'));
    }

}
