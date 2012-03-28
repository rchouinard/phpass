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
use Phpass\Exception\InvalidArgumentException;

/**
 * PHPass Bcrypt Hash Adapter
 *
 * @package PHPass
 * @subpackage Hash
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */
class Bcrypt extends Base
{

    /**
     * String identifier to use when generating new hash values.
     *
     * @var string
     */
    protected $_identifier = '2a';

    /**
     * Logarithmic cost value used when generating new hash values.
     *
     * @var integer
     */
    protected $_iterationCountLog2 = 12;

    /**
     * List of valid hash identifier strings.
     *
     * @var array
     */
    protected $_validIdentifiers = array ('2a', '2x', '2y');

    /**
     * Class constructor.
     *
     * @see \Phpass\Hash\Base::__construct()
     */
    public function __construct(Array $options = array ())
    {
        parent::__construct($options);
        $this->_itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    }

    /**
     * Set adapter options.
     *
     * Expects an associative array of option keys and values used to configure
     * the hash adapter instance.
     *
     * <dl>
     *   <dt>iterationCountLog2</dt>
     *     <dd>A logarithmic value between 4 and 31, inclusive. This value
     *     used to calculate the cost factor associated with generating a new
     *     hash value. A higher number means a higher cost, with each increment
     *     doubling the cost. Defaults to 12.</dd>
     *   <dt>identifier</dt>
     *     <dd>Hash identifier to use when generating a new hash value.
     *     Supported identifiers are 2a, 2x, and 2y. Defaults to 2a.</dd>
     * </dl>
     *
     * @param array $options
     *   Associative array of adapter options.
     * @return void
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
    }

    /**
     * Check if a string contains a valid salt value for this adapter.
     *
     * @param string $input
     *   String
     * @return boolean
     */
    //public function verifySalt($input)
    //{
    //    return (1 === preg_match('/^\$2[axy]{1}\$\d{2}\$[\.\/0-9A-Za-z]{22}$/', substr($input, 0, 29)));
    //}

    /**
     * Check if a string contains a valid hash value for this adapter.
     *
     * @param string $input
     * @return boolean
     */
    //public function verifyHash($input)
    //{
    //    return ($this->verifySalt($input) && 1 === preg_match('/^[\.\/0-9A-Za-z]{31}$/', substr($input, 29)));
    //}

    //public function verify($input)
    //{
    //    return ($this->verifyHash($input) || $this->verifySalt($input));
    //}

    /**
     * Generate a salt string suitable for PHP's crypt() function
     *
     * Bcrypt::genSalt() generates a 29-character salt string which can be
     * passed to crypt() in order to use the CRYPT_BLOWFISH hash type. The salt
     * consists of a string beginning with a compatible hash identifier, a
     * two-digit cost factor, and a 22-character encoded salt string using the
     * characters "./0-9A-Za-z", separated by "$".
     *
     * @see \Phpass\Hash\Adapter::genSalt()
     */
    public function genSalt($input = null)
    {
        if (!$input) {
            $input = $this->_getRandomBytes(16);
        }

        // Hash identifier
        $output = '$' . $this->_identifier . '$';

        // Cost factor
        $output .= chr(ord('0') + $this->_iterationCountLog2 / 10);
        $output .= chr(ord('0') + $this->_iterationCountLog2 % 10);
        $output .= '$';

        // Random salt data
        $i = 0;
        do {
            $c1 = ord($input[$i++]);
            $output .= $this->_itoa64[$c1 >> 2];
            $c1 = ($c1 & 0x03) << 4;
            if ($i >= 16) {
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

        // $II$CC$SSSSSSSSSSSSSSSSSSSSSS
        return $output;
    }

}