<?php
/**
 * PHP Password Library
 *
 * @package PHPass
 * @subpackage Exceptions
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */

/**
 * @namespace
 */
namespace Phpass\Exception;
use Phpass\Exception;

/**
 * @see \Phpass\Exception
 */
require_once 'Phpass/Exception.php';

/**
 * PHP Password Library
 *
 * @package PHPass
 * @subpackage Exceptions
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */
class UnexpectedValueException extends \UnexpectedValueException implements Exception
{
}