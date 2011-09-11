<?php
/**
 * Portable PHP password hashing framework.
 *
 * @package PHPass
 * @subpackage Exceptions
 * @category Cryptography
 * @author Solar Designer <solar at openwall.com>
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license Public Domain
 * @link http://www.openwall.com/phpass/ Original phpass project page.
 * @version 0.5
 */

/**
 * @namespace
 */
namespace Phpass\Exception;

/**
 * @see \Phpass\Exception
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
 * @license Public Domain
 * @link http://www.openwall.com/phpass/ Original phpass project page.
 * @version 0.5
 */
class UnexpectedValueException extends \UnexpectedValueException implements \Phpass\Exception
{
}