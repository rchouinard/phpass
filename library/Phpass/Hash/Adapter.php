<?php
/**
 * PHP Password Library
 *
 * @package PHPass\Hashes
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */

/**
 * @namespace
 */
namespace Phpass\Hash;

/**
 * Hash adapter interface
 *
 * @package PHPass\Hashes
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
interface Adapter
{

    /**
     * Return a hashed string.
     *
     * @param string $password
     *   The string to be hashed.
     * @param string $salt
     *   An optional salt string to base the hashing on. If not provided, the
     *   adapter will generate a new secure salt value.
     * @return string
     *   Returns the hashed string.
     */
    public function crypt($password, $salt = null);

    /**
     * Return a salt string suitable for use with the current adapter.
     *
     * @param string $input
     *   Optional random data to be used when generating the salt. Requirements
     *   for this parameter may very by adapter.
     * @return string
     *   Returns the generated salt string.
     */
    public function genSalt($input = null);

}