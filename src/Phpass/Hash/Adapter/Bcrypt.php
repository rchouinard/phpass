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

use Phpass\Exception\InvalidArgumentException;

/**
 * Bcrypt hash adapter
 *
 * @package PHPass\Hashes
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
class Bcrypt extends Base
{

    /**
     * String identifier used to generate new hash values.
     *
     * @var string
     */
    protected $_identifier = '2y';

    /**
     * Logarithmic cost value used to generate new hash values.
     *
     * @var integer
     */
    protected $_iterationCountLog2 = 12;

    /**
     * Alphabet used in itoa64 conversions.
     *
     * @var string
     */
    protected $_itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    /**
     * List of valid hash identifier strings.
     *
     * @var array
     */
    protected $_validIdentifiers = array ('2a', '2x', '2y');

    /**
     * Class constructor.
     *
     * @param Array $options
     *   Associative array of adapter options.
     * @return void
     *   Returns nothing; it's a constructor.
     * @see self::setOptions()
     * @see Base::__construct()
     */
    public function __construct(Array $options = array ())
    {
        // Versions of PHP < 5.3.7 only support the 2a identifier
        if (version_compare(PHP_VERSION, '5.3.7', '<')) {
            $this->_identifier = '2a';
            $this->_validIdentifiers = array ('2a');
        }

        parent::__construct($options);
    }

    /**
     * Generate a salt string compatible with this adapter.
     *
     * @param string $input
     *   Optional random 128-bit string to use when generating the salt.
     * @return string
     *   Returns the generated salt string.
     */
    public function genSalt($input = null)
    {
        if (!$input) {
            $input = $this->_getRandomBytes(16);
        }

        // Hash identifier
        $identifier = $this->_identifier;

        // Cost factor - "4" to "04"
        $costFactor  = chr(ord('0') + $this->_iterationCountLog2 / 10);
        $costFactor .= chr(ord('0') + $this->_iterationCountLog2 % 10);

        // Salt string
        $salt = $this->_encode64($input, 16);

        // $II$CC$SSSSSSSSSSSSSSSSSSSSSS
        return '$' . $identifier . '$' . $costFactor . '$' . $salt;
    }

    /**
     * Set adapter options.
     *
     * Expects an associative array of option keys and values used to configure
     * this adapter.
     *
     * <dl>
     *   <dt>iterationCountLog2</dt>
     *     <dd>Base-2 logarithm of the iteration count for the underlying
     *     Blowfish-based hashing algorithm. Must be in range 4 - 31.
     *     Defaults to 12.</dd>
     *   <dt>identifier</dt>
     *     <dd>Hash identifier to use when generating new hash values.
     *     Supported identifiers are 2a, 2x, and 2y. Defaults to 2y in PHP
     *     versions 5.3.7 and above, 2a otherwise.</dd>
     * </dl>
     *
     * @param Array $options
     *   Associative array of adapter options.
     * @return self
     *   Returns an instance of self to support method chaining.
     * @throws InvalidArgumentException
     *   Throws an InvalidArgumentException if a provided option key contains
     *   an invalid value.
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
                    if ($value < 4 || $value > 31) {
                        throw new InvalidArgumentException('Iteration count must be between 4 and 31');
                    }
                    $this->_iterationCountLog2 = $value;
                    break;
                case 'identifier':
                    $value = strtolower($value);
                    if (!in_array($value, $this->_validIdentifiers)) {
                        throw new InvalidArgumentException('Invalid hash identifier');
                    }
                    $this->_identifier = $value;
                    break;
                default:
                    break;
            }
        }

        return $this;
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
        return ($this->verifySalt(substr($input, 0, -31)) && 1 === preg_match('/^[\.\/0-9A-Za-z]{31}$/', substr($input, -31)));
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
        $appearsValid = (1 === preg_match('/^\$2[axy]{1}\$\d{2}\$[\.\/0-9A-Za-z]{22}$/', $input));
        if ($appearsValid) {
            $costFactor = (int) substr($input, 4, 2);
            if ($costFactor < 4 || $costFactor > 31) {
                $appearsValid = false;
            }
        }

        return $appearsValid;
    }

    /**
     * Encode raw data to characters in the itoa64 alphabet.
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
            $c1 = ord($input[$i++]);
            $output .= $this->_itoa64[$c1 >> 2];
            $c1 = ($c1 & 0x03) << 4;
            if ($i >= $count) {
                $output .= $this->_itoa64[$c1];
                break;
            }

            $c2 = ord($input[$i++]);
            $c1 |= $c2 >> 4;
            $output .= $this->_itoa64[$c1];
            $c1 = ($c2 & 0x0f) << 2;

            $c2 = ord($input[$i++]);
            $c1 |= $c2 >> 6;
            $output .= $this->_itoa64[$c1];
            $output .= $this->_itoa64[$c2 & 0x3f];
        } while (1);

        return $output;
    }

}
