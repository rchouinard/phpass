<?php
/**
 * PHP Password Library
 *
 * @package PHPass
 * @subpackage Tests
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */

/**
 * @namespace
 */
namespace Phpass\Exception;
use Phpass\Exception\UnexpectedValueException;

/**
 * @see PHPUnit_Framework_TestCase
 */
require_once 'PHPUnit/Framework/TestCase.php';

/**
 * @see Phpass\Exception\UnexpectedValueException
 */
require_once 'Phpass/Exception/UnexpectedValueException.php';

/**
 * PHP Password Library
 *
 * @package PHPass
 * @subpackage Tests
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */
class UnexpectedValueExceptionTest extends \PHPUnit_Framework_TestCase
{

    /**
     * @test
     * @return void
     */
    public function exceptionClassImplementsCorrectInterface()
    {
        $exception = new UnexpectedValueException('Test exception');

        $this->assertInstanceOf(
            '\Phpass\Exception',
            $exception
        );

        $this->assertInstanceOf(
            '\UnexpectedValueException',
            $exception
        );

    }

}