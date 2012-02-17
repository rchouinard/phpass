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
 * PHPass PBKDF2 Hash Adapter
 *
 * @package PHPass
 * @subpackage Hash
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */
class Pbkdf2 extends Base
{

    /**
     * Hashing algorithm used by the PBKDF2 implementation.
     *
     * Defaults to sha256.
     *
     * @var string
     */
    protected $_algo;

    /**
     * @see \Phpass\Hash\Base::__construct()
     */
    public function __construct(Array $options = array ())
    {
        parent::__construct($options);

        $this->_algo = $this->_algo ?: 'sha256';
        $this->_iterationCountLog2 = $this->_iterationCountLog2 ?: 12;
    }

    /**
     * @see \Phpass\Hash\Base::crypt()
     */
    public function crypt($password, $setting = null)
    {
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
     * @see \Phpass\Hash\Adapter::genSalt()
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
     *   The plain-text password string.
     * @param string $salt
     *   Salt value used by the HMAC function.
     * @param integer $iterationCount
     *   Optional; Number of iterations for key stretching.
     * @param integer $keyLength
     *   Optional; Length of derived key.
     * @param string $algo
     *   Optional; Algorithm to use when generating HMAC digest.
     * @return string
     *   Returns the raw hash value.
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