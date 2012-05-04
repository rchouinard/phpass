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
 * Extended DES hash adapter
 *
 * @package PHPass\Hashes
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
class ExtDes extends Base
{

    /**
     * Number of rounds used to generate new hashes.
     *
     * @var integer
     */
    protected $_iterationCount = 5001;

    /**
     * Generate a salt string compatible with this adapter.
     *
     * @param string $input
     *   Optional random 24-bit string to use when generating the salt.
     * @return string
     *   Returns the generated salt string.
     */
    public function genSalt($input = null)
    {
        if (!$input) {
            $input = $this->_getRandomBytes(3);
        }

        // Cost must be between 1 and 2^24 - 1
        $count = min($this->_iterationCount + 1, (1 << 24) - 1);
        // This should be odd to avoid revealing weak DES keys
        if ($count % 2) {
            --$count;
        }

        // Hash identifier
        $identifier = '_';

        // Cost factor
        $costFactor  = $this->_itoa64[$count & 0x3f];
        $costFactor .= $this->_itoa64[($count >> 0x06) & 0x3f];
        $costFactor .= $this->_itoa64[($count >> 0x0c) & 0x3f];
        $costFactor .= $this->_itoa64[($count >> 0x12) & 0x3f];

        // Salt string
        $salt = $this->_encode64($input, 3);

        return $identifier . $costFactor . $salt;
    }

    /**
     * Set adapter options.
     *
     * Expects an associative array of option keys and values used to configure
     * this adapter.
     *
     * <dl>
     *   <dt>iterationCount</dt>
     *     <dd>Number of rounds to use when generating new hashes. Must be
     *     between 1 and 2^24-1. Defaults to 5001.</dd>
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
                    $value = (1 << (int) $value);
                    // Fall through
                case 'iterationcount':
                    $value = (int) $value;
                    if ($value < 1 || $value > (1 << 24) - 1) {
                        throw new InvalidArgumentException('Iteration count must be between 1 and 16777215');
                    }
                    $this->_iterationCountLog2 = $value;
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
        return ($this->verifySalt(substr($input, 0, -11)) && 1 === preg_match('/^[\.\/0-9A-Za-z]{11}$/', substr($input, -11)));
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
        return (1 === preg_match('/^_[\.\/0-9A-Za-z]{8}$/', $input));
    }

}