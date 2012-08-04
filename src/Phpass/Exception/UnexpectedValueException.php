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
 * Unexpected value exception
 *
 * Exception thrown if a value does not match with a set of values. This
 * typically happens when a function calls another function and expects the
 * return value to be of a certian type or value, not including arithmetic or
 * buffer related errors.
 *
 * @package PHPass\Exceptions
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
class UnexpectedValueException extends \UnexpectedValueException implements Exception
{
}
