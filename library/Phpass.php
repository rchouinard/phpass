<?php
/**
 * PHP Password Library
 *
 * @package PHPass
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */

use Phpass\Exception\InvalidArgumentException,
    Phpass\Exception\RuntimeException,
    Phpass\Exception\UnexpectedValueException;

/**
 * @see Phpass\Hash\Base
 */
require_once 'Phpass/Hash/Base.php';

/**
 * @see Phpass\Exception\InvalidArgumentException
 */
require_once 'Phpass/Exception/InvalidArgumentException.php';

/**
 * @see Phpass\Exception\RuntimeException
 */
require_once 'Phpass/Exception/RuntimeException.php';

/**
 * @see Phpass\Exception\UnexpectedValueException
 */
require_once 'Phpass/Exception/UnexpectedValueException.php';

/**
 * PHP Password Library
 *
 * @package PHPass
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */
class Phpass
{

    /**
     * Instance of adapter to use for hashing.
     *
     * Defaults to an instance of Phpass\Hash\Blowfish configured with
     * iterationCountLog2 set to 12 if none is given otherwise.
     *
     * @see Phpass::setAdapter()
     * @see Phpass::setOptions()
     * @var Phpass\Hash
     */
    protected $_adapter;

    /**
     * Algorithm to use with HMAC.
     *
     * Defaults to sha256 if not otherwise specified.
     *
     * @see Phpass::setOptions()
     * @see Phpass::$_hmacKey
     * @var string
     */
    protected $_hmacAlgo;

    /**
     * Key to use with HMAC.
     *
     * If set, the password string given to either Phpass::hashPassword()
     * or Phpass::checkPassword() is passed through hash_hmac() before
     * it is passed to the adapter.
     *
     * @see Phpass::setOptions()
     * @see Phpass::$_hmacAlgo
     * @var string
     */
    protected $_hmacKey;

    /**
     * Class constructor.
     *
     * There are three ways to configure the class via the constructor.
     *
     *  * Pass an associative array containing class options as the first
     *    argument to the constructor.
     *
     *         <?php
     *         $phpass = new Phpass(array (
     *             'adapter' => array (
     *                 'type' => 'blowfish',
     *                 'options' => array (
     *                     'iterationCountLog2' => 12
     *                 )
     *             ),
     *             'hmacAlgo' => 'sha256',
     *             'hmacKey' => 'mySuperSecretKey'
     *         ));
     *
     *  * Pass a pre-configured adapter as the first argument to the
     *    constructor. This method blocks passing non-adapter options to the
     *    class via the constructor, though. Developers would need to call
     *    Phpass::setOptions() in order to do so.
     *
     *         <?php
     *         $adapter = new Phpass\Hash\Blowfish(array (
     *             'iterationCountLog2' => 12
     *         ));
     *         $phpass = new Phpass($adapter);
     *         $phpass->setOptions(array (
     *             'hmacAlgo' => 'sha256',
     *             'hmacKey' => 'mySuperSecretKey'
     *         ));
     *
     *  * Pass a string representing the name of an adapter as the first
     *    constructor argument, and an associative array of adapter options as
     *    the second. This method also necessitates the use of
     *    Phpass::setOptions() in order to pass class options.
     *
     *         <?php
     *         $phpass = new Phpass('blowfish', array (
     *             'iterationCountLog2' => 12
     *         ));
     *         $phpass->setOptions(array (
     *             'hmacAlgo' => 'sha256',
     *             'hmacKey' => 'mySuperSecretKey'
     *         ));
     *
     * @see Phpass::setOptions()
     * @param array|Phpass\Hash|string $options
     *   Either an associative array of options, a string naming an adapter,
     *   or an instance of a class implementing Phpass\Adapter.
     * @param array $adapterOptions
     *   Optional; If the first argument is a string, the second should be an
     *   associative array of adapter options.
     * @return void
     * @throws Phpass\Exception\InvalidArgumentException
     *   Thrown if $options isn't valid.
     */
    public function __construct($options = array (), Array $adapterOptions = array ())
    {
        // Support for method 2, above
        if ($options instanceof Phpass\Hash) {
            $options = array ('adapter' => $options);
        }

        // Support for method 3, above
        if (is_string($options)) {
            $options = array (
                'adapter' => array (
                    'type' => $options,
                    'options' => $adapterOptions
                )
            );
        }

        // Sanity check
        if (!is_array($options)) {
            $type = gettype($options);
            throw new InvalidArgumentException("Expected array or instance of Phpass\Adapter; ${type} given");
        }

        // Default adapter and options
        if (!isset($options['adapter'])) {
            $options['adapter'] = array (
                'type' => 'blowfish',
                'options' => array (
                    'iterationCountLog2' => 12
                )
            );
        }

        $this->setOptions($options);
    }

    /**
     * Set class options.
     *
     * <dt>adapter</dt>
     *   <dd>Optional; Either an instance of a class which implements
     *   Phpass\Hash or an associative array. The array should contain at
     *   least a 'type' key with the name of an adapter as a string. An
     *   'options' key may also be specified, containing an associative array
     *   of adapter options. See Phpass\Hash\Base::setOptions() for
     *   details.</dd>
     *
     * <dt>hmacKey</dt>
     *   <dd>Optional; Key used to generate HMAC hashes. If omitted, HMAC
     *   hashing is disabled.</dd>
     *
     * <dt>hmacAlgo</dt>
     *   <dd>Optional; String naming one of the many hashing algorithms
     *   available. A full list may be retrieved from the hash_algos()
     *   function. Defaults to sha256.</dd>
     *
     * @see Phpass\Hash\Base::setOptions()
     * @param array $options
     *   An associative array containing class options.
     * @return Phpass
     *   Instance of Phpass for chaining.
     * @throws Phpass\Exception\RuntimeException
     *   Thrown if an HMAC key has been provided, but the required hash
     *   extension isn't loaded.
     * @throws Phpass\Exception\InvalidArgumentException
     *   Thrown if an HMAC key has been provided, but the chosen algorithm
     *   isn't supported on the system.
     */
    public function setOptions(Array $options)
    {
        $options = array_change_key_case($options, CASE_LOWER);

        if (isset($options['adapter'])) {
            if ($options['adapter'] instanceof Phpass\Hash) {
                $this->setAdapter($options['adapter']);
            } else if (is_array($options['adapter'])) {
                $adapter = $options['adapter']['type'];
                $adapterOptions = $options['adapter']['options'];
                $this->setAdapter($adapter, $adapterOptions);
            }
        }

        if (isset($options['hmackey'])) {
            if (!extension_loaded('hash')) {
                throw new RuntimeException('Required extension "hash" is not loaded');
            }
            $this->_hmacKey = $options['hmackey'];
            $this->_hmacAlgo = isset($options['hmacalgo']) ? $options['hmacalgo'] : 'sha256';
            if (!in_array($this->_hmacAlgo, hash_algos())) {
                throw new InvalidArgumentException("Hash algorithm '{$this->_hashAlgo}' is not supported on this system");
            }
        }

        return $this;
    }

    /**
     * Get the currently configured adapter instance.
     *
     * @return Phpass\Hash
     *   Instance of a class which implements Phpass\Hash.
     * @throws Phpass\Exception\RuntimeException
     *   Thrown if no adapter is configured.
     */
    public function getAdapter()
    {
        if (!$this->_adapter instanceof Phpass\Hash) {
            throw new RuntimeException('There is no adapter set');
        }

        return $this->_adapter;
    }

    /**
     * Set a configured adapter instance.
     *
     * @param Phpass\Hash|string $adapter
     *   Either a string naming an adapter or an instance of a class
     *   implementing Phpass\Hash.
     * @param array $options
     *   Optional; If the first argument is a string, the second should be an
     *   associative array of adapter options.
     * @return Phpass
     *   Instance of Phpass for chaining.
     * @throws Phpass\Exception\RuntimeException
     *   Thrown if the adapter isn't supported on the system.
     */
    public function setAdapter($adapter, Array $options = array ())
    {
        if (!$adapter instanceof Phpass\Hash) {
            $adapter = Phpass\Hash\Base::factory($adapter, $options);
        }

        if (!$adapter->isSupported()) {
            $className = get_class($this->_adapter);
            throw new RuntimeException("Adapter '${className}' is not supported on this system");
        }

        $this->_adapter = $adapter;
        return $this;
    }

    /**
     * Check that a password string matches a given hash.
     *
     * @param string $password
     *   The plain-text password string.
     * @param string $storedHash
     *   The stored hash value to compare against.
     * @return boolean
     *   True if password string matches the stored hash, false otherwise.
     */
    public function checkPassword($password, $storedHash)
    {
        $hash = $this->_crypt($password, $storedHash);
        return $hash == $storedHash;
    }

    /**
     * Generate a hash from a password string.
     *
     * @param string $password
     *   the plain-text password string.
     * @return string
     *   Hashed version of the password string.
     */
    public function hashPassword($password)
    {
        return $this->_crypt($password);
    }

    /**
     * Proxy method to Phpass\Hash::crypt()
     *
     * Additional processing of the password string is performed if
     * Phpass::$_hmacKey is set.
     *
     * @param string $password
     *   The plain-text password string.
     * @param string $salt
     *   Optional; The salt or stored hash value used to generate a new hash.
     * @return string
     *   Hashed version of the password string.
     * @throws Phpass\Exception\UnexpectedValueException
     *   Thrown if the adapter returns an invalid hash value.
     */
    protected function _crypt($password, $salt = null)
    {
        if (isset($this->_hmacKey)) {
            $password = hash_hmac($this->_hmacAlgo, $password, $this->_hmacKey);
        }
        $adapter = $this->getAdapter();
        $hash = $adapter->crypt($password, $salt);
        if (!$adapter->isValid($hash)) {
            throw new UnexpectedValueException('The adapter returned an invalid hash');
        }

        return $hash;
    }

}