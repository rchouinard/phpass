<?php
/**
 * Portable PHP password hashing framework.
 *
 * @package PHPass
 * @category Cryptography
 * @author Solar Designer <solar at openwall.com>
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license Public Domain
 * @link http://www.openwall.com/phpass/ Original phpass project page.
 * @version 0.5
 */

/**
 * @see \Phpass\Adapter\Base
 */
require_once 'Phpass/Adapter/Base.php';

/**
 * @see \Phpass\Exception\InvalidArgumentException
 */
require_once 'Phpass/Exception/InvalidArgumentException.php';

/**
 * @see \Phpass\Exception\RuntimeException
 */
require_once 'Phpass/Exception/RuntimeException.php';

/**
 * @see \Phpass\Exception\UnexpectedValueException
 */
require_once 'Phpass/Exception/UnexpectedValueException.php';

/**
 * Portable PHP password hashing framework.
 *
 * @package PHPass
 * @category Cryptography
 * @author Solar Designer <solar at openwall.com>
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license Public Domain
 * @link http://www.openwall.com/phpass/ Original phpass project page.
 * @version 0.5
 */
class Phpass
{

    /**
     * @var \Phpass\Adapter
     */
    protected $_adapter;

    /**
     * Constructor
     *
     * I'm still debating on the API here. I can see three valid ways of
     * instantiating the class, all of which have merit.
     *
     * The first, and most verbose method, is to use an $options array to pass
     * everything, including the adapter type and adapter options. This is the
     * most flexible method, and is probably preferred moving forward.
     *
     *   $phpass = new \Phpass($myOptionsArray);
     *
     * The second is to pass in a previously instantiated adapter, presumably
     * already configured. This method will probably continue to be supported
     * along with the first.
     *
     *   $adapter = new \Phpass\Adapter\Blowfish($myAdapterOptions);
     *   $phpass = new \Phpass($adapter);
     *
     * The third way is in-line with the way Zend_Db and similar operate. The
     * first argument is a string giving the name of the adapter type, and the
     * second is an array of adapter options.
     *
     *   $phpass = new \Phpass('blowfish', $myAdapterOptions);
     *
     * All three methods are currently supported, although this may change as
     * I continue to use the class and gain feedback from other developers.
     *
     * @param array|\Phpass\Adapter|string $options
     * @param array $adapterOptions
     * @return void
     * @throws \Phpass\Exception\InvalidArgumentException
     */
    public function __construct($options = array (), Array $adapterOptions = array ())
    {
        // Support for method 2, above
        if ($options instanceof \Phpass\Adapter) {
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
            throw new \Phpass\Exception\InvalidArgumentException(
                "Expected array or instance of \Phpass\Adapter; {$type} given"
            );
        }

        // Default adapter and options
        if (empty($options)) {
            $options = array (
                'adapter' => array (
                    'type' => 'blowfish',
                    'options' => array (
                        'iterationCountLog2' => 8
                    )
                )
            );
        }

        $this->setOptions($options);
    }

    /**
     * Set library options
     *
     * Currently, the only option is 'adapter', which may be either a concrete
     * instance of \Phpass\Adapter or an array. The adapter array should contain
     * at least a 'type' key with the name of the desired adapter, and
     * optionally an 'options' key containing an array of options to pass to the
     * adapter.
     *
     * array (
     *     'adapter' => array (
     *         'type' => 'blowfish',
     *         'options' => array ()
     *     )
     * )
     *
     * @param array $options
     * @return \Phpass
     */
    public function setOptions(Array $options)
    {
        $options = array_change_key_case($options, CASE_LOWER);

        if (isset($options['adapter'])) {
            if ($options['adapter'] instanceof \Phpass\Adapter) {
                $this->setAdapter($options['adapter']);
            } else if (is_array($options['adapter'])) {
                $adapter = $options['adapter']['type'];
                $adapterOptions = $options['adapter']['options'];
                $this->setAdapter($adapter, $adapterOptions);
            }
        }

        return $this;
    }

    /**
     * Return the currently configured adapter
     *
     * @return \Phpass\Adapter
     * @throws \Phpass\Exception\RuntimeException
     */
    public function getAdapter()
    {
        if (!$this->_adapter instanceof \Phpass\Adapter) {
            throw new \Phpass\Exception\RuntimeException('There is no adapter set');
        }

        return $this->_adapter;
    }

    /**
     * Pass in a configured adapter
     *
     * @param \Phpass\Adapter|string $adapter
     * @param array $options
     * @return \Phpass
     * @throws \Phpass\Exception\RuntimeException
     */
    public function setAdapter($adapter, Array $options = array ())
    {
        if (!$adapter instanceof \Phpass\Adapter) {
            $adapter = \Phpass\Adapter\Base::factory($adapter, $options);
        }

        // Adapter isn't supported
        if (!$adapter->isSupported()) {
            $className = get_class($this->_adapter);

            throw new \Phpass\Exception\RuntimeException(
                "Adapter '${className}' is not supported on this system"
            );
        }

        $this->_adapter = $adapter;
        return $this;
    }

    /**
     * Check that a given password matches a given hash
     *
     * @param string $password
     * @param string $storedHash
     * @return boolean
     */
    public function checkPassword($password, $storedHash)
    {
        $hash = $this->_crypt($password, $storedHash);
        return $hash == $storedHash;
    }

    /**
     * Generate a hash from the given password
     *
     * @param string $password
     * @return string
     */
    public function hashPassword($password)
    {
        return $this->_crypt($password);
    }

    /**
     * @param string $password
     * @param string $salt
     * @return string
     * @throws \Phpass\Exception\UnexpectedValueException
     */
    protected function _crypt($password, $salt = null)
    {
        $adapter = $this->getAdapter();
        $hash = $adapter->crypt($password, $salt);
        if (!$adapter->isValid($hash)) {
            throw new \Phpass\Exception\UnexpectedValueException(
                'The adapter returned an invalid hash'
            );
        }

        return $hash;
    }

}