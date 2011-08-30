<?php
/**
 * Portable PHP password hashing framework.
 *
 * This is a reimplementation of the popular PHPass library using PHP5
 * conventions.
 *
 * @package PHPass
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
 * @category Cryptography
 * @author Solar Designer <solar at openwall.com>
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license Public Domain
 * @link http://www.openwall.com/phpass/ Original phpass project page.
 * @version 0.4
 */
class Phpass
{

    /**
     * String of characters used in integer to ASCII conversions.
     *
     * @var string
     */
    protected $_itoa64;

    /**
     * Number used to calculate iteration count for password stretching.
     *
     * This number is expressed as the log2 of the actual iteration count. This
     * means that a value of 4 means 16 iterations (log2(16) = 4), while a
     * value of 16 means 65,536 itarations.
     *
     * @var integer
     */
    protected $_iterationCountLog2;

    /**
     * Flag indicating whether the weaker portable hash algorithm should be used
     * by default.
     *
     * Portable hashes are the default when both Blowfish and Extended DES are
     * not available on the system. Setting this flag to true will always use
     * the portable method even when those methods are available.
     *
     * @var boolean
     */
    protected $_portableHashes;

    /**
     * Storage for randomized data pool.
     *
     * @var string
     */
    protected $_randomState;

    /**
     * Class constructor.
     *
     * @see $_iterationCountLog2
     * @see $_portableHashes
     *
     * @param integer $iterationCountLog2 Number used to calculate iteration
     *     count for password stretching.
     * @param boolean $portableHashes Flag indicating whether the weaker
     *     portable hash algorithm should be used by default.
     * @return void
     */
    public function __construct($iterationCountLog2 = 8, $portableHashes = false)
    {
        $this->_itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

        if ($iterationCountLog2 < 4 || $iterationCountLog2 > 31) {
            $iterationCountLog2 = 8;
        }
        $this->_iterationCountLog2 = $iterationCountLog2;

        $this->_portableHashes = $portableHashes;

        $this->_randomState = microtime();
        if (function_exists('getmypid')) {
            $this->_randomState .= getmypid();
        }
    }

    /**
     * Fetch a random pool of data.
     *
     * @param integer $count Number of bytes to return.
     * @return string String containing the number of bytes requested.
     */
    protected function _getRandomBytes($count)
    {
        $output = '';
        if (is_readable('/dev/urandom') && ($fh = @fopen('/dev/urandom', 'rb'))) {
            $output = fread($fh, $count);
            fclose($fh);
        }

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

    /**
     * @param string $input
     * @param integer $count
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
     * Create a portable hash.
     *
     * @param string $password
     * @param string $setting
     * @return string
     */
    protected function _cryptPrivate($password, $setting)
    {
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
     * Generate a salt suitable for use with portable hash algorithm.
     *
     * @param string $input
     * @return string
     */
    protected function _gensaltPrivate($input)
    {
        $output = '$P$';
        $output .= $this->_itoa64[min($this->_iterationCountLog2 + 5, 30)];
        $output .= $this->_encode64($input, 6);

        return $output;
    }

    /**
     * Generate a salt suitable for use with Extended DES.
     *
     * @param string $input
     * @return string
     */
    protected function _gensaltExtended($input)
    {
        $countLog2 = min($this->_iterationCountLog2 + 8, 24);
        // This should be odd to not reveal weak DES keys, and the
        // maximum valid value is (2**24 - 1) which is odd anyway.
        $count = (1 << $countLog2) - 1;

        $output = '_';
        $output .= $this->_itoa64[$count & 0x3f];
        $output .= $this->_itoa64[($count >> 6) & 0x3f];
        $output .= $this->_itoa64[($count >> 12) & 0x3f];
        $output .= $this->_itoa64[($count >> 18) & 0x3f];

        $output .= $this->_encode64($input, 3);

        return $output;
    }

    /**
     * Generate a salt suitable for use with Blowfish.
     *
     * @param string $input
     * @return string
     */
    protected function _gensaltBlowfish($input)
    {
        // This one needs to use a different order of characters and a
        // different encoding scheme from the one in encode64() above.
        // We care because the last character in our encoded string will
        // only represent 2 bits.  While two known implementations of
        // bcrypt will happily accept and correct a salt string which
        // has the 4 unused bits set to non-zero, we do not want to take
        // chances and we also do not want to waste an additional byte
        // of entropy.
        $itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

        $output = '$2a$';
        $output .= chr(ord('0') + $this->_iterationCountLog2 / 10);
        $output .= chr(ord('0') + $this->_iterationCountLog2 % 10);
        $output .= '$';

        $i = 0;
        do {
            $c1 = ord($input[$i++]);
            $output .= $itoa64[$c1 >> 2];
            $c1 = ($c1 & 0x03) << 4;
            if ($i >= 16) {
                $output .= $itoa64[$c1];
                break;
            }

            $c2 = ord($input[$i++]);
            $c1 |= $c2 >> 4;
            $output .= $itoa64[$c1];
            $c1 = ($c2 & 0x0f) << 2;

            $c2 = ord($input[$i++]);
            $c1 |= $c2 >> 6;
            $output .= $itoa64[$c1];
            $output .= $itoa64[$c2 & 0x3f];
        } while (1);

        return $output;
    }

    /**
     * Create a hash from a given password.
     *
     * @param string $password Password to hash.
     * @return string Hashed representation of the given password.
     */
    public function hashPassword($password)
    {
        $random = '';

        // Blowfish is available.
        if (CRYPT_BLOWFISH == 1 && !$this->_portableHashes) {
            $random = $this->_getRandomBytes(16);
            $hash = crypt($password, $this->_gensaltBlowfish($random));
            if (strlen($hash) == 60) {
                return $hash;
            }
        }

        // Blowfish is not available, but Extended DES is.
        if (CRYPT_EXT_DES == 1 && !$this->_portableHashes) {
            if (strlen($random) < 3) {
                $random = $this->_getRandomBytes(3);
            }
            $hash = crypt($password, $this->_gensaltExtended($random));
            if (strlen($hash) == 20) {
                return $hash;
            }
        }

        // Neither Blowfish nor Extended DES are available, or portable hashes
        // are enabled.
        if (strlen($random) < 6) {
            $random = $this->_getRandomBytes(6);
        }
        $hash = $this->_cryptPrivate($password, $this->_gensaltPrivate($random));
        if (strlen($hash) == 34) {
            return $hash;
        }

        // Returning '*' on error is safe here, but would _not_ be safe
        // in a crypt(3)-like function used _both_ for generating new
        // hashes and for validating passwords against existing hashes.
        return '*';
    }

    /**
     * Test a given password against an existing hash.
     *
     * @param string $password Supplied password to test.
     * @param string $storedHash Password hash to test against.
     * @return boolean Returns true if the supplied password matches the hash,
     *     false otherwise.
     */
    public function checkPassword($password, $storedHash)
    {
        $hash = $this->_cryptPrivate($password, $storedHash);
        if ($hash[0] == '*') {
            $hash = crypt($password, $storedHash);
        }

        return $hash == $storedHash;
    }

}