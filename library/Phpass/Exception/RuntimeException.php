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
 * Runtime exception
 *
 * Exception thrown if an error which can only be found on runtime occurs.
 *
 * @package PHPass\Exceptions
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
class RuntimeException extends \RuntimeException implements Exception
{
}
