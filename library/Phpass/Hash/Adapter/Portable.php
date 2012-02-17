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
namespace Phpass\Hash\Adapter;

/**
 * PHPass Portable Hash Adapter
 *
 * @package PHPass
 * @subpackage Hash
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */
class Portable extends Base
{

    /**
     * @see \Phpass\Hash\Adapter::crypt()
     */
    public function crypt($password, $setting = null)
    {
        if (!$setting) {
            $setting = $this->genSalt();
        }

        $output = '*0';
        if (substr($setting, 0, 2) == $output) {
            $output = '*1';
        }

        $id = substr($setting, 0, 3);
        // We use "$P$", phpBB3 uses "$H$" for the same thing
        if ($id != '$P$' && $id != '$H$') {
            return $output;
        }

        $countLog2 = strpos($this->_itoa64, $setting[3]);
        if ($countLog2 < 7 || $countLog2 > 30) {
            return $output;
        }

        $count = 1 << $countLog2;

        $salt = substr($setting, 4, 8);
        if (strlen($salt) != 8) {
            return $output;
        }

        // Original comment from PasswordHash class:
        // We're kind of forced to use MD5 here since it's the only
        // cryptographic primitive available in all versions of PHP
        // currently in use.  To implement our own low-level crypto
        // in PHP would result in much worse performance and
        // consequently in lower iteration counts and hashes that are
        // quicker to crack (by non-PHP code).
        $hash = md5($salt . $password, true);
        do {
            $hash = md5($hash . $password, true);
        } while (--$count);

        $output = substr($setting, 0, 12);
        $output .= $this->_encode64($hash, 16);

        return $output;
    }

    /**
     * @see \Phpass\Hash\Adapter::genSalt()
     */
    public function genSalt($input = null)
    {
        if (!$input) {
            $input = $this->_getRandomBytes(6);
        }

        $output = '$P$';
        $output .= $this->_itoa64[min($this->_iterationCountLog2 + 5, 30)];
        $output .= $this->_encode64($input, 6);

        return $output;
    }

}