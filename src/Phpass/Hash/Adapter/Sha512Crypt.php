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
 * SHA512 crypt hash adapter
 *
 * @package PHPass\Hashes
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 * @since 2.1.0
 */
class Sha512Crypt extends Sha256Crypt
{

    /**
     * Number of rounds used to generate new hashes.
     *
     * @var integer
     */
    protected $_iterationCount = 60000;

    /**
     * String identifier used to generate new hash values.
     *
     * @var string
     */
    protected $_identifier = '6';

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
        return ($this->verifySalt(substr($input, 0, -86)) && 1 === preg_match('/^[\.\/0-9A-Za-z]{86}$/', substr($input, -86)));
    }

}
