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

namespace PHPassLib;

/**
 * Exception marker interface
 *
 * All internal library exception classes implement this interface. This allows
 * the exception classes to extend other exceptions and still be recognized as
 * instances of PHPassLib\Exception.
 *
 * @package PHPassLib\Exceptions
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
interface Exception
{
}
