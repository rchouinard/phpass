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
use Phpass\Exception\InvalidArgumentException;

/**
 * PHPass portable hash adapter
 * 
 * Implements a hashing algorithm compatible with the original Openwall phpass
 * portable hash.
 *
 * @package PHPass\Hashes
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
class Portable extends Base
{

    /**
     * Logarithmic cost value used when generating new hash values.
     *
     * @var integer
     */
    protected $_iterationCountLog2 = 12;

    /**
     * Flag indicating if new hashes should use phpBB hash identifiers.
     *
     * By default, new hashes will use the $P$ identifier. If this flag is set
     * to true, new hashes will use the $H$ identifier.
     *
     * @var boolean
     */
    protected $_phpBBCompat = false;

    /**
     * Set adapter options.
     *
     * Expects an associative array of option keys and values used to configure
     * the hash adapter instance.
     *
     * <dl>
     *   <dt>iterationCountLog2</dt>
     *     <dd>A logarithmic value between 7 and 30, inclusive. This value
     *     used to calculate the cost factor associated with generating a new
     *     hash value. A higher number means a higher cost, with each increment
     *     doubling the cost. Defaults to 12.</dd>
     *   <dt>phpBBCompat</dt>
     *     <dd>Boolean flag used to determine whether new hash strings should
     *     use phpBB compatible hash identifiers (true) or the standard phpass
     *     portable identifier (false). Defaults to false.</dd>
     * </dl>
     *
     * @param Array $options
     *   Associative array of adapter options.
     * @return Bcrypt
     * @see Base::setOptions()
     */
    public function setOptions(Array $options)
    {
        parent::setOptions($options);

        $options = array_change_key_case($options, CASE_LOWER);
        foreach ($options as $key => $value) {
            switch ($key) {
                case 'iterationcountlog2':
                    $value = (int) $value;
                    if ($value < 7 || $value > 30) {
                        throw new InvalidArgumentException('Iteration count must be a logarithmic value between 7 and 30');
                    }
                    $this->_iterationCountLog2 = $value;
                    break;
                case 'phpbbcompat':
                    $this->_phpBBCompat = (bool) $value;
                    break;
                default:
                    break;
            }
        }

        return $this;
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
        $setting = $salt;
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
     * Generate a salt string suitable for the crypt() method.
     *
     * Portable::genSalt() generates a 12-character salt string which can be
     * passed to crypt() in order to use Openwall's portable PHP hash. The salt
     * is a string beginning with the hash identifier $P$ followed by 1-byte of
     * iteration count and 8-bytes of salt.
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

        $output = $this->_phpBBCompat ? '$H$' : '$P$';
        $output .= $this->_itoa64[min($this->_iterationCountLog2 + 5, 30)];
        $output .= $this->_encode64($input, 6);

        return $output;
    }

}