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
use Phpass\Exception\RuntimeException;

/**
 * @see PHPUnit_Framework_TestCase
 */
require_once 'PHPUnit/Framework/TestCase.php';

/**
 * @see Phpass\Exception\RuntimeException
 */
require_once 'Phpass/Exception/RuntimeException.php';

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
class RuntimeExceptionTest extends \PHPUnit_Framework_TestCase
{

    /**
     * @test
     * @return void
     */
    public function exceptionClassImplementsCorrectInterface()
    {
        $exception = new RuntimeException('Test exception');

        $this->assertInstanceOf(
            '\Phpass\Exception',
            $exception
        );

        $this->assertInstanceOf(
            '\RuntimeException',
            $exception
        );

    }

}