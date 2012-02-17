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
namespace Phpass;
use Phpass\Hash\Adapter,
    Phpass\Hash\Adapter\Blowfish,
    Phpass\Exception\InvalidArgumentException,
    Phpass\Exception\RuntimeException;

/**
 * PHPass Hash Class
 *
 * This class provides a simple API for working with the various hash adapters.
 * When instantiated with no arguments, it creates an instance of
 * \Phpass\Hash\Adapter\Blowfish, configured for 2^12 (or 4,096) iterations.
 * It is also possible to configure the class to use HMAC to provide some extra
 * security where needed.
 *
 * <code>
 * <?php
 * // Just use the defaults (works well in most cases)
 * $phpassHash = new \Phpass\Hash;
 *
 * // Generate a password hash
 * $passwordHash = $phpassHash->hashPassword($password);
 *
 * // Check a password
 * if ($phpassHash->checkPassword($password, $passwordHash)) {
 *     // ...
 * }
 * </code>
 *
 * @package PHPass
 * @subpackage Hash
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */
class Hash
{

    /**
     * Instance of the adapter to use for hashing password strings.
     *
     * @var \Phpass\Hash\Adapter
     */
    protected $_adapter;

    /**
     * Name of selected HMAC hashing algorithm.
     *
     * See hash_algos() for a list of supported algorithms.
     *
     * @var string
     */
    protected $_hmacAlgo;

    /**
     * Shared secret for generating the HMAC variant of the password string.
     *
     * @var string
     */
    protected $_hmacKey;

    /**
     * Class constructor.
     *
     * Accepts either an associative array of option key value pairs, or a
     * concrete instance of \Phpass\Hash\Adapter. If neither is given, or if the
     * 'adapter' option key is omitted, an instance of
     * \Phpass\Hash\Adapter\Blowfish is used by default.
     *
     * <code>
     * <?php
     * // Just use the defaults (works for most cases)
     * $phpassHash = new \Phpass\Hash;
     *
     * // Customize the adapter
     * $adapter = new \Phpass\Hash\Adapter\Pbkdf2(array (
     *     'iterationCountLog2' => 12 // 2^12 = 4096 iterations
     * ));
     * $phpassHash = new \Phpass\Hash($adapter);
     *
     * // Customize the adapter as well as use additional HMAC hashing
     * $options = array (
     *     'adapter' => new \Phpass\Hash\Adapter\ExtDes,
     *     'hmacKey' => 'mys3cr3tk3y',
     *     'hmacAlgo' => 'sha512'
     * );
     * $phpassHash = new \Phpass\Hash($options);
     * </code>
     *
     * @param array|\Phpass\Hash\Adapter $options
     *   Either an associative array of options, or an instance of
     *   \Phpass\Hash\Adapter.
     * @return void
     */
    public function __construct($options = array ())
    {
        // Default adapter
        $this->_adapter = new Blowfish(array (
            'iterationCountLog2' => 12 // 2^12 = 4096 iterations
        ));

        // Default HMAC algorithm
        $this->_hmacAlgo = 'sha256';

        if ($options instanceof Adapter) {
            $options = array (
                'adapter' => $options
            );
        }

        if (!is_array($options)) {
            throw new InvalidArgumentException('Expected either an array, or an instance of Phpass\\Hash\\Adapter.');
        }

        $this->setOptions($options);
    }

    /**
     * Set the adapter to use for hashing password strings.
     *
     * @param \Phpass\Hash\Adapter $adapter
     *   An instance of \Phpass\Hash\Adapter.
     * @return \Phpass\Hash
     */
    public function setAdapter(Adapter $adapter)
    {
        $this->_adapter = $adapter;
        return $this;
    }

    /**
     * Retrieve the adapter used for hashing password strings.
     *
     * @return \Phpass\Hash\Adapter
     */
    public function getAdapter()
    {
        return $this->_adapter;
    }

    /**
     * Set instance options.
     *
     * Available options:
     *   - adapter: An instance of Phpass\Hash\Adapter.
     *   - hmacKey: A string used as the key in optional HMAC hashing.
     *   - hmacAlgo: The name of the hashing algorithm to use for HMAC hashing.
     *
     * @param array $options
     *   An associative array of options.
     * @return \Phpass\Hash
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
                        throw new RuntimeException("Given hash algorithm '${value}' is not supported.");
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
     * Check if a password string matches a given hash value.
     *
     * @param string $password
     *   The password string to check.
     * @param string $storedHash
     *   The hash string to check against.
     * @return boolean
     *   Returns true if the password matches the hash, and false otherwise.
     */
    public function checkPassword($password, $storedHash)
    {
        $hash = $this->_crypt($password, $storedHash);
        return ($hash == $storedHash);
    }

    /**
     * Create a hash from a given password using the configured adapter.
     *
     * @param string $password
     *   The password string from which to derive the hash value.
     * @return string
     *   Returns the derived hash value.
     */
    public function hashPassword($password)
    {
        return $this->_crypt($password);
    }

    /**
     * Derive a hash value from the given password string, optionally using a
     * pre-calculated salt.
     *
     * If self::$_hmacKey is set, this method will generate the HMAC hash of
     * the password string before passing the value to the adapter.
     *
     * @param string $password
     *   The password string.
     * @param string $salt
     *   The hash string which contains the stored salt value.
     * @return string
     *   Returns the derived hash value.
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