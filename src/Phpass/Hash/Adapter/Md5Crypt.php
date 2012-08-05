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

namespace Phpass\Hash\Adapter;

/**
 * MD5 crypt hash adapter
 *
 * @package PHPass\Hashes
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 * @since 2.1.0
 */
class Md5Crypt extends Base
{

    /**
     * Generate a salt string compatible with this adapter.
     *
     * @param string $input
     *   Optional random 48-bit string to use when generating the salt.
     * @return string
     *   Returns the generated salt string.
     */
    public function genSalt($input = null)
    {
        if (!$input) {
            $input = $this->_getRandomBytes(6);
        }

        $identifier = '1';
        $salt = $this->_encode64($input, 6);

        return '$' . $identifier . '$' . $salt . '$';
    }

    /**
     * Check if a hash string is valid for the current adapter.
     *
     * @since 2.1.0
     * @param string $input
     *   Hash string to verify.
     * @return boolean
     *   Returns true if the input string is a valid hash value, false
     *   otherwise.
     */
    public function verifyHash($input)
    {
        return ($this->verifySalt(substr($input, 0, -22)) && 1 === preg_match('/^[\.\/0-9A-Za-z]{22}$/', substr($input, -22)));
    }

    /**
     * Check if a salt string is valid for the current adapter.
     *
     * @since 2.1.0
     * @param string $input
     *   Salt string to verify.
     * @return boolean
     *   Returns true if the input string is a valid salt value, false
     *   otherwise.
     */
    public function verifySalt($input)
    {
        return (1 === preg_match('/^\$1\$[\.\/0-9A-Za-z]{0,8}\$?$/', $input));
    }

}
