<?php
/**
 * Portable PHP password hashing framework.
 *
 * @package PHPass
 * @subpackage Exceptions
 * @category Cryptography
 * @author Solar Designer <solar at openwall.com>
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link http://www.openwall.com/phpass/ Original phpass project page.
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */

/**
 * @namespace
 */
namespace Phpass\Exception;
use Phpass\Exception;

/**
 * @see Phpass\Exception
 */
require_once 'Phpass/Exception.php';

/**
 * Portable PHP password hashing framework.
 *
 * @package PHPass
 * @subpackage Exceptions
 * @category Cryptography
 * @author Solar Designer <solar at openwall.com>
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link http://www.openwall.com/phpass/ Original phpass project page.
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */
class InvalidArgumentException extends \InvalidArgumentException implements Exception
{
}