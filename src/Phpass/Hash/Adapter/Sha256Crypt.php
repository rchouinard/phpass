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
 * SHA256 crypt hash adapter
 *
 * @package PHPass\Hashes
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 * @since 2.1.0
 */
class Sha256Crypt extends Base
{

    /**
     * Number of rounds used to generate new hashes.
     *
     * @var integer
     */
    protected $_iterationCount = 80000;

    /**
     * String identifier used to generate new hash values.
     *
     * @var string
     */
    protected $_identifier = '5';

    /**
     * Generate a salt string compatible with this adapter.
     *
     * @param string $input
     *   Optional random 96-bit string to use when generating the salt.
     * @return string
     *   Returns the generated salt string.
     */
    public function genSalt($input = null)
    {
        if (!$input) {
            $input = $this->_getRandomBytes(12);
        }

        $identifier = $this->_identifier;

        $rounds = '';
        if ($this->_iterationCount != 5000) {
            $rounds = 'rounds=' . $this->_iterationCount . '$';
        }

        $salt = $this->_encode64($input, 12);

        return '$' . $identifier . '$' . $rounds . $salt . '$';
    }

    /**
     * Set adapter options.
     *
     * Expects an associative array of option keys and values used to configure
     * the hash adapter instance.
     *
     * <dl>
     *   <dt>iterationCount</dt>
     *     <dd>An integer value between 1,000 and 999,999,999, inclusive. This
     *     value determines the cost factor associated with generating a new
     *     hash value. A higher number means a higher cost. Defaults to
     *     40,000.</dd>
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
                    $value = (1 << (int) $value);
                    // Fall through
                case 'iterationcount':
                    $value = (int) $value;
                    if ($value < 1000 || $value > 999999) {
                        throw new InvalidArgumentException('Iteration count must be between 1000 and 999999');
                    }
                    $this->_iterationCount = $value;
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
        return ($this->verifySalt(substr($input, 0, -43)) && 1 === preg_match('/^[\.\/0-9A-Za-z]{43}$/', substr($input, -43)));
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
        $regex = '/^\$' . $this->_identifier . '\$(?:rounds=(\d{4,9})\$)?([\.\/0-9A-Za-z]{0,16})\$?$/';
        $matches = array ();

        $appearsValid = (1 === preg_match($regex, $input, $matches));
        if ($appearsValid) {
            $rounds = (int) $matches[1];
            $salt = $matches[2];

            // If rounds parameter is in the salt position, the configuration
            // is probably not what the user intends. We could let it pass and
            // it'll "work", but we'll fail it for now.
            if (strpos($salt, 'rounds=') === 0) {
                $appearsValid = false;
            }

            if (!empty ($matches[1]) && ($rounds < 1000 || $rounds > 999999999)) {
                $appearsValid = false;
            }
        }

        return $appearsValid;
    }

}
