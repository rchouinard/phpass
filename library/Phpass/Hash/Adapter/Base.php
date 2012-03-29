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
use Phpass\Hash\Adapter,
    Phpass\Exception\InvalidArgumentException;

/**
 * Hash adapter base class
 *
 * @package PHPass\Hashes
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
abstract class Base implements Adapter
{

    /**
     * Binary logarithm value used in password stretching.
     *
     * This number determines the cost of calculating hash values for the
     * various adapters.
     *
     * Each adapter may treat this number differently. Generally, a calculated
     * value of 256 means that the password string is iteratively hashed 256
     * times, which increases the time and CPU cost associated with generating
     * the hash value.
     *
     * @var integer
     */
    protected $_iterationCountLog2 = 12;

    /**
     * Alphabet used in itoa64 conversions.
     *
     * @var string
     */
    protected $_itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

    /**
     * Cached random data.
     *
     * This value is used when better methods of generating random data are
     * unavailable.
     *
     * @var string
     */
    protected $_randomState;


    /**
     * Class constructor.
     *
     * @param Array $options
     *   Associative array of adapter options.
     * @return void
     */
    public function __construct(Array $options = array ())
    {
        $this->_randomState = microtime();
        if (function_exists('getmypid')) {
            $this->_randomState .= getmypid();
        }

        $this->setOptions($options);
    }

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
        if (!$salt) {
            $salt = $this->genSalt();
        }
        return crypt($password, $salt);
    }

    /**
     * Set adapter options.
     *
     * @param Array $options
     *   Associative array of adapter options.
     * @return Base
     */
    public function setOptions(Array $options)
    {
        $options = array_change_key_case($options, CASE_LOWER);
        foreach ($options as $key => $value) {
            switch ($key) {
                case 'iterationcountlog2':
                    $this->_iterationCountLog2 = (int) $value;
                    break;
                default:
                    break;
            }
        }
        
        return $this;
    }

    /**
     * Encode raw data to alphanumeric characters.
     * 
     * Each byte of the raw string is converted to its ASCII ordinal value and
     * encoded as a series of ASCII characters from the itoa64 character set.
     *
     * @param string $input
     *   Raw binary data to encode.
     * @param integer $count
     *   Number of bytes to encode.
     * @return string
     *   Returns the encoded data as a string.
     */
    protected function _encode64($input, $count)
    {
        $output = '';
        $i = 0;
        do {
            $value = ord($input[$i++]);
            $output .= $this->_itoa64[$value & 0x3f];
            if ($i < $count) {
                $value |= ord($input[$i]) << 8;
            }
            $output .= $this->_itoa64[($value >> 6) & 0x3f];
            if ($i++ >= $count) {
                break;
            }
            if ($i < $count) {
                $value |= ord($input[$i]) << 16;
            }
            $output .= $this->_itoa64[($value >> 12) & 0x3f];
            if ($i++ >= $count) {
                break;
            }
            $output .= $this->_itoa64[($value >> 18) & 0x3f];
        } while ($i < $count);

        return $output;
    }

    /**
     * Generate a string of pseudo-random bytes.
     *
     * @param integer $count
     *   The length of the desired string of bytes. Must be a positive integer.
     * @return string
     *   Returns the generated string of bytes.
     */
    protected function _getRandomBytes($count)
    {
        // Try OpenSSL's random generator
        if (function_exists('openssl_random_pseudo_bytes')) {
            $strongCrypto = false;
            $output = openssl_random_pseudo_bytes($count, $strongCrypto);
            if ($strongCrypto && strlen($output) == $count) {
                return $output;
            }
        }

        // Try reading from /dev/urandom, if present
        $output = '';
        if (is_readable('/dev/urandom') && ($fh = fopen('/dev/urandom', 'rb'))) {
            $output = fread($fh, $count);
            fclose($fh);
        }

        // Fall back to a locally generated "random" string
        if (strlen($output) < $count) {
            $output = '';
            for ($i = 0; $i < $count; $i += 16) {
                $this->_randomState = md5(microtime() . $this->_randomState);
                $output .= md5($this->_randomState, true);
            }
            $output = substr($output, 0, $count);
        }

        return $output;
    }

}