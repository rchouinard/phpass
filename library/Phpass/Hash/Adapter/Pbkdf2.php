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
namespace Phpass\Hash\Adapter;

/**
 * PBKDF2 hash adapter
 *
 * @package PHPass\Hashes
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
class Pbkdf2 extends Base
{

    /**
     * Hashing algorithm used by the PBKDF2 implementation.
     *
     * @var string
     */
    protected $_algo = 'sha256';

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
     * @see Adapter::crypt()
     */
    public function crypt($password, $salt = null)
    {
        $setting = $salt;
        if (!$setting) {
            $setting = $this->genSalt();
        }

        // Return blowfish error string *0 or *1 on failure
        // Portable adapter does this, so we do it here to remain consistent
        $output = '*0';
        if (substr($setting, 0, 2) == $output) {
            $output = '*1';
        }

        if (substr($setting, 0, 6) != '$p5v2$') {
            return $output;
        }

        $countLog2 = $countLog2 = strpos($this->_itoa64, $setting[6]);
        if ($countLog2 < 0 || $countLog2 > 30) {
            return $output;
        }
        $count = 1 << $countLog2;

        $salt = substr($setting, 7, 8);
        if (strlen($salt) != 8) {
            return $output;
        }

        $hash = $this->_pbkdf2($password, $salt, $count, 24, $this->_algo);

        $output = substr($setting, 0, 16);
        $output .= $this->_encode64($hash, 24);

        return $output;
    }

    /**
     * Generate a salt string suitable for the crypt() method.
     *
     * Pbkdf2::genSalt() generates a 16-character salt string which can be
     * passed to crypt(). The salt consists of a string beginning with a
     * compatible hash identifier, one byte of iteration count, and an
     * 8-byte encoded salt followed by "$".
     *
     * @param string $input
     *   Optional random data to be used when generating the salt. Must contain
     *   at least 6 bytes of data.
     * @return string
     *   Returns the generated salt string.
     * @see Adapter::genSalt()
     */
    public function genSalt($input = null)
    {
        if (!$input) {
            $input = $this->_getRandomBytes(6);
        }

        // PKCS #5, version 2
        // Python implementation uses $p5k2$, but we're not using a compatible
        // string. https://www.dlitz.net/software/python-pbkdf2/
        $output = '$p5v2$';

        // Iteration count between 1 and 1,073,741,824
        $output .= $this->_itoa64[min(max($this->_iterationCountLog2, 0), 30)];

        // 8-byte (64-bit) salt value, as recommended by the standard
        $output .= $this->_encode64($input, 6);

        // $p5v2$CSSSSSSSS$
        return $output . '$';
    }

    /**
     * Internal implementation of PKCS #5 v2.0.
     *
     * This implementation passes tests using vectors given in RFC 6070 s.2,
     * PBKDF2 HMAC-SHA1 Test Vectors. Vectors given for PBKDF2 HMAC-SHA2 at
     * http://stackoverflow.com/questions/5130513 also pass.
     *
     * @param string $password
     *   The string to be hashed.
     * @param string $salt
     *   Salt value used by the HMAC function.
     * @param integer $iterationCount
     *   Number of iterations for key stretching.
     * @param integer $keyLength
     *   Length of derived key.
     * @param string $algo
     *   Algorithm to use when generating HMAC digest.
     * @return string
     *   Returns the raw hash string.
     */
    protected function _pbkdf2($password, $salt, $iterationCount = 1000, $keyLength = 20, $algo = 'sha1')
    {
        $hashLength = strlen(hash($algo, null, true));
        $keyBlocks = ceil($keyLength / $hashLength);
        $derivedKey = '';

        for ($block = 1; $block <= $keyBlocks; ++$block) {
            $iteratedBlock = $currentBlock = hash_hmac($algo, $salt . pack('N', $block), $password, true);
            for ($iteration = 1; $iteration < $iterationCount; ++$iteration) {
                $iteratedBlock ^= $currentBlock = hash_hmac($algo, $currentBlock, $password, true);
            }

            $derivedKey .= $iteratedBlock;
        }

        return substr($derivedKey, 0, $keyLength);
    }

}