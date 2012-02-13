<?php
/**
 * PHP Password Library
 *
 * @package PHPass
 * @subpackage Strength
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */

/**
 * @namespace
 */
namespace Phpass;

/**
 * PHP Password Library
 *
 * @package PHPass
 * @subpackage Strength
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */
interface Strength
{

    /**
     * Calculate the strength of a given password.
     *
     * @param string $password
     *   The plain-text password string.
     * @return integer
     *   A numeric value representing the calculated password strength.
     */
    public function check($password);

}