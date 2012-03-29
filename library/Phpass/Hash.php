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
namespace Phpass;
use Phpass\Hash\Adapter,
    Phpass\Hash\Adapter\Bcrypt,
    Phpass\Exception\InvalidArgumentException,
    Phpass\Exception\RuntimeException;

/**
 * Hash class
 *
 * Provides a simple API for working with the various hash adapters. If the
 * class is constructed with no arguments, it will construct a bcrypt
 * adapter with default settings for use internally.
 * 
 * If an optional HMAC key is provided, password strings will be hashed using
 * the chosen HMAC algorithm and the supplied key before being passed to the
 * adapter. HMAC-SHA256 is used by default.
 *
 *     <?php
 *     // Just use the defaults (works well in most cases)
 *     $phpassHash = new \Phpass\Hash;
 *     
 *     // Generate a password hash
 *     $passwordHash = $phpassHash->hashPassword($password);
 *     
 *     // Check a password
 *     if ($phpassHash->checkPassword($password, $passwordHash)) {
 *         // Passwords match!
 *     }
 *
 * @package PHPass\Hashes
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
class Hash
{

    /**
     * Instance of the adapter to use for hashing strings.
     *
     * @var Adapter
     */
    protected $_adapter;

    /**
     * Name of selected hashing algorithm.
     *
     * See \hash_algos() for a list of supported algorithms.
     *
     * @var string
     */
    protected $_hmacAlgo = 'sha256';

    /**
     * Shared secret key used for generating the HMAC variant of the string.
     *
     * @var string
     */
    protected $_hmacKey;

    /**
     * Class constructor.
     *
     * Expects either an associative array of options, or an instance of a
     * class implementing the Adapter interface. If neither is given, or if the
     * 'adapter' option key is omitted, an instance of the Bcrypt adapter is
     * created internally by default.
     *
     *     <?php
     *     // Just use the defaults (works for most cases)
     *     $phpassHash = new \Phpass\Hash;
     *     
     *     // Customize the adapter
     *     $adapter = new \Phpass\Hash\Adapter\Pbkdf2(array (
     *         'iterationCountLog2' => 12 // 2^12 iterations
     *     ));
     *     $phpassHash = new \Phpass\Hash($adapter);
     *     
     *     // Customize the adapter as well as use additional HMAC hashing
     *     $options = array (
     *         'adapter' => new \Phpass\Hash\Adapter\ExtDes,
     *         'hmacKey' => 'mys3cr3tk3y'
     *     );
     *     $phpassHash = new \Phpass\Hash($options);
     *
     * @param Array|Adapter $options
     *   Either an associative array of options, or an instance of Adapter.
     * @return void
     * @throws InvalidArgumentException
     *   An InvalidArgumentException is thrown if a value other than an Adapter
     *   instance or options array is passed to the constructor.
     */
    public function __construct($options = array ())
    {
        $this->_adapter = new Bcrypt;
        if ($options instanceof Adapter) {
            $options = array ('adapter' => $options);
        } 

        if (!is_array($options)) {
            throw new InvalidArgumentException('Expected an instance of Phpass\\Hash\\Adapter or an associative array of options.');
        }

        $this->setOptions($options);
    }

    /**
     * Set the adapter to use for hashing strings.
     *
     * @param Adapter $adapter
     *   An instance of a class implementing the Adapter interface.
     * @return Hash
     */
    public function setAdapter(Adapter $adapter)
    {
        $this->_adapter = $adapter;
        return $this;
    }

    /**
     * Retrieve the adapter used for hashing strings.
     *
     * @return Adapter
     */
    public function getAdapter()
    {
        return $this->_adapter;
    }

    /**
     * Set options.
     *
     * <dl>
     *   <dt>adapter</dt>
     *     <dd>Instance of a class implementing the Adapter interface.</dd>
     *   <dt>hmacKey</dt>
     *     <dd>Shared secret key used for generating the HMAC variant of the
     *     string.</dd>
     *   <dt>hmacAlgo</dt>
     *     <dd>Name of selected hashing algorithm. See \hmac_algos() for a list
     *     of supported algorithms.</dd>
     * </dl>
     *
     * @param Array $options
     *   An associative array of options.
     * @return Hash
     * @throws RuntimeException
     *   A RuntimeException is thrown if HMAC options are passed in, but the
     *   hash extension is not loaded.
     * @throws InvalidArgumentException
     *   An InvalidArgumentException is thrown if a value does not match what
     *   is expected for the option key.
     */
    public function setOptions(Array $options)
    {
        $options = array_change_key_case($options, CASE_LOWER);
        if (array_key_exists('hmackey', $options) || array_key_exists('hmacalgo', $options)) {
            if (!extension_loaded('hash')) {
                throw new RuntimeException("Required extension 'hash' is not loaded.");
            }
        }

        foreach ($options as $option => $value) {
            switch ($option) {
                case 'adapter':
                    if (!$value instanceof Adapter) {
                        throw new InvalidArgumentException("Value of key 'adapter' must be an instance of Phpass\\Hash\\Adapter.");
                    }
                    $this->setAdapter($value);
                    break;
                case 'hmackey':
                    $this->_hmacKey = (string) $value;
                    break;
                case 'hmacalgo':
                    if (!in_array($value, hash_algos())) {
                        throw new InvalidArgumentException("Given hash algorithm '${value}' is not supported by this system.");
                    }
                    $this->_hmacAlgo = $value;
                    break;
                default:
                    break;
            }
        }

        return $this;
    }

    /**
     * Check if a string matches a given hash value.
     *
     * @param string $password
     *   The string to check.
     * @param string $storedHash
     *   The hash string to check against.
     * @return boolean
     *   Returns true if the string matches the hash string, and false
     *   otherwise.
     */
    public function checkPassword($password, $storedHash)
    {
        $hash = $this->_crypt($password, $storedHash);
        return ($hash == $storedHash);
    }

    /**
     * Return a hashed string using the configured adapter.
     *
     * @param string $password
     *   The string to be hashed.
     * @return string
     *   Returns the hashed string.
     */
    public function hashPassword($password)
    {
        return $this->_crypt($password);
    }

    /**
     * Return a hashed string, optionally using a pre-calculated salt.
     *
     * If Hash::$_hmacKey is set, this method will generate the HMAC hash of
     * the password string before passing the value to the adapter.
     *
     * @param string $password
     *   The string to be hashed.
     * @param string $salt
     *   An optional salt string to base the hashing on. If not provided, the
     *   adapter will generate a new secure salt value.
     * @return string
     *   Returns the hashed string.
     */
    protected function _crypt($password, $salt = null)
    {
        if (isset($this->_hmacKey)) {
            $password = hash_hmac($this->_hmacAlgo, $password, $this->_hmacKey);
        }
        $adapter = $this->getAdapter();
        $hash = $adapter->crypt($password, $salt);

        return $hash;
    }

}