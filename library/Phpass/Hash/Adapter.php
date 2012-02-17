<?php
/**
 * PHP Password Library
 *
 * @package PHPass
 * @subpackage Hash
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */

/**
 * @namespace
 */
namespace Phpass\Hash;

/**
 * PHPass Hash Adapter Interface
 *
 * @package PHPass
 * @subpackage Hash
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */
interface Adapter
{

    /**
     * Generate a hash based on the password string.
     *
     * @param string $password
     *   The plain-text password string.
     * @param string $salt
     *   Optional; The salt or stored hash value used to generate a new hash.
     * @return string
     *   Returns the calculated hash value of the password string.
     */
    public function crypt($password, $salt = null);

    /**
     * Generate a salt string suitable for use with the adapter.
     *
     * @param string $input
     *   Optional; Random data used to generate the salt.
     * @return string
     *   Returns a generated salt string.
     */
    public function genSalt($input = null);

}