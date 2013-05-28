<?php
/**
 * PHP Password Library
 *
 * @package PHPassLib\Exceptions
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */

namespace PHPassLib\Exception;

use PHPassLib\Exception;

/**
 * Invalid argument exception
 *
 * Exception thrown thrown if an argument does not match with the expected
 * value.
 *
 * @package PHPassLib\Exceptions
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
class InvalidArgumentException extends \InvalidArgumentException implements Exception
{
}
