<?php
/**
 * PHP Password Library
 *
 * @package PHPass\Exceptions
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */

namespace Phpass\Exception;

use Phpass\Exception;

/**
 * Invalid argument exception
 *
 * Exception thrown thrown if an argument does not match with the expected
 * value.
 *
 * @package PHPass\Exceptions
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
class InvalidArgumentException extends \InvalidArgumentException implements Exception
{
}
