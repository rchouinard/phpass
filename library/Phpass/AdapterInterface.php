<?php
/**
 * Portable PHP password hashing framework.
 *
 * @package PHPass
 * @subpackage Adapters
 * @category Cryptography
 * @author Solar Designer <solar at openwall.com>
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license Public Domain
 * @link http://www.openwall.com/phpass/ Original phpass project page.
 * @version 0.4
 */

/**
 * Portable PHP password hashing framework.
 *
 * @package PHPass
 * @subpackage Adapters
 * @category Cryptography
 * @author Solar Designer <solar at openwall.com>
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license Public Domain
 * @link http://www.openwall.com/phpass/ Original phpass project page.
 * @version 0.4
 */
interface Phpass_AdapterInterface
{

    /**
     * Generate a string suitable for use as a salt.
     *
     * @param string $input
     * @return string
     */
    public function genSalt($input);

    /**
     * Create a hash for the given password using the supplied salt.
     *
     * @param string $password
     * @param string $salt
     * @return string
     */
    public function crypt($password, $salt);

    /**
     * @return boolean
     */
    public function isSupported();

}