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

/**
 * @namespace
 */
namespace Phpass;

/**
 * Exception marker interface
 *
 * All internal library exception classes implement this interface. This allows
 * the exception classes to extend other exceptions and still be recognized as
 * instances of Phpass\Exception.
 *
 * @package PHPass\Exceptions
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
interface Exception
{
}