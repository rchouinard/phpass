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
 * @namespace
 */
namespace Phpass;

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
interface Adapter
{

    /**
     * @param string $password
     * @param string $salt
     * @return string
     */
    public function crypt($password, $salt = null);

    /**
     * @param string $input
     * @return string
     */
    public function genSalt($input);


    /**
     * @return boolean
     */
    public function isSupported();

    /**
     * @param string $hash
     * @return boolean
     */
    public function isValid($hash);

}