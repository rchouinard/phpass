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
     * String identifier to use when generating new hash values.
     *
     * @var string
     */
    protected $_identifier = '2y';

    /**
     * Logarithmic cost value used when generating new hash values.
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
     * (non-PHPdoc)
     * @see \Phpass\Hash\Adapter\Base::crypt()
     */
    public function crypt($password, $salt = null)
    {
        if (!$salt) {
            $salt = $this->genSalt();
        }
        $hash =  crypt($password, $salt);

        // XXX: Work around https://bugs.php.net/bug.php?id=61852
        if (!$this->verifyHash($hash)) {
            $hash = ($salt != '*0') ? '*0' : '*1';
        }

        return $hash;
    }

    /**
     * Generate a salt string suitable for the crypt() method.
     *
     * A valid salt string begins with either $2a$, $2x$, or $2y$, a two-digit
     * cost factor, and a 128-bit salt encoded as 22 characters in the regex
     * range [./A-Za-z0-9].
     *
     * @param string $input
     *   Optional 128-bits of random data to be used when generating the salt.
     * @return string
     *   Returns the generated salt string.
     * @see Adapter::genSalt()
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
     * the hash adapter instance.
     *
     * <dl>
     *   <dt>iterationCountLog2</dt>
     *     <dd>A logarithmic value between 4 and 31, inclusive. This value is
     *     used to calculate the cost factor associated with generating a new
     *     hash value. A higher number means a higher cost, with each increment
     *     doubling the cost. Defaults to 12.</dd>
     *   <dt>identifier</dt>
     *     <dd>Hash identifier to use when generating a new hash value.
     *     Supported identifiers are 2a, 2x, and 2y. Defaults to 2y.</dd>
     * </dl>
     *
     * @param Array $options
     *   Associative array of adapter options.
     * @return Bcrypt
     * @throws InvalidArgumentException
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
                        throw new InvalidArgumentException('Iteration count must be a logarithmic value between 4 and 31');
                    }
                    $this->_iterationCountLog2 = $value;
                    break;
                case 'identifier':
                    if (!in_array($value, $this->_validIdentifiers)) {
                        throw new InvalidArgumentException('Invalid hash identifier.');
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
     * Check if a string is either a valid hash or salt value for this adapter.
     *
     * @param string $input
     * @return boolean
     */
    public function verify($input)
    {
        return ($this->verifyHash($input) || $this->verifySalt($input));
    }

    /**
     * Check if a string contains a valid hash value for this adapter.
     *
     * @param string $input
     * @return boolean
     */
    public function verifyHash($input)
    {
        return ($this->verifySalt($input) && 1 === preg_match('/^[\.\/0-9A-Za-z]{31}$/', substr($input, 29)));
    }

    /**
     * Check if a string contains a valid salt value for this adapter.
     *
     * @param string $input
     * @return boolean
     */
    public function verifySalt($input)
    {
        return (1 === preg_match('/^\$2[axy]{1}\$\d{2}\$[\.\/0-9A-Za-z]{22}$/', substr($input, 0, 29)));
    }

    /**
     * (non-PHPdoc)
     * @see Base::_encode64()
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