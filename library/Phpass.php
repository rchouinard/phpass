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
 * @version 0.4
 */

require_once 'Phpass/Adapter.php';

/**
 * Portable PHP password hashing framework.
 *
 * @package PHPass
 * @category Cryptography
 * @author Solar Designer <solar at openwall.com>
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license Public Domain
 * @link http://www.openwall.com/phpass/ Original phpass project page.
 * @version 0.4
 */
class Phpass
{

    /**
     * @var Phpass_Adapter
     */
    protected $_adapter;

    /**
     * @var boolean
     */
    protected $_allowFallback;

    /**
     * @param array|integer $options
     * @param boolean $portableHashes
     * @return void
     */
    public function __construct($options = array (), $portableHashes = false)
    {
        $this->_allowFallback = false;

        // Handle arguments for backwards compatibility.
        $iterationCountLog2 = 8;
        if (is_int($options)) {
            $iterationCountLog2 = (int) $options;
            if ($portableHashes) {
                $options = array (
                    'adapter' => array (
                        'adapter' => 'Phpass_Adapter_Portable',
                        'options' => array (
                            'iterationCountLog2' => $iterationCountLog2
                        )
                    )
                );
            } else {
                $options = array (
                    'adapter' => array (
                        'adapter' => 'Phpass_Adapter_Blowfish',
                        'options' => array (
                            'iterationCountLog2' => $iterationCountLog2
                        )
                    ),
                    'allowFallback' => true
                );
            }
        }

        $this->setOptions($options);
    }

    /**
     * @param array $options
     * @return Phpass
     */
    public function setOptions(Array $options)
    {
        $options = array_change_key_case($options, CASE_LOWER);

        // Fallback mode will register the Portable adapter if the registered
        // adapter isn't supported.
        if (isset($options['allowfallback'])) {
            $this->_allowFallback = (bool) $options['allowfallback'];
        }

        // Adapter can be an adapter instance or an array containing the adapter
        // name or class and configuration options.
        if (isset($options['adapter'])) {
            if ($options['adapter'] instanceof Phpass_Adapter) {
                $this->setAdapter($options['adapter']);
            } else if (is_array($options['adapter'])) {
                $adapter = $options['adapter']['adapter'];
                $adapterOptions = $options['adapter']['options'];
                $this->setAdapter($adapter, $adapterOptions);
            }
        }

        return $this;
    }

    /**
     * @return Phpass_Adapter;
     */
    public function getAdapter()
    {
        // No adapter is registered.
        if (!$this->_adapter) {
            require_once 'Phpass/Exception/MissingAdapter.php';
            throw new Phpass_Exception_MissingAdapter(
                'There is no adapter set.'
            );
        }

        return $this->_adapter;
    }

    /**
     * @param Phpass_Adapter|string $adapter
     * @param array $options
     * @return Phpass
     */
    public function setAdapter($adapter, Array $options = array ())
    {
        if (!$adapter instanceof Phpass_Adapter) {
            $adapter = Phpass_Adapter::factory($adapter, $options);
        }

        // Adapter isn't supported, but fallback is on.
        if (!$adapter->isSupported() && $this->_allowFallback) {
            $adapter = Phpass_Adapter::factory(
                'Phpass_Adapter_Portable',
                $options
            );
        }

        // Adapter isn't supported, and fallback is off.
        if (!$adapter->isSupported() && !$this->_allowFallback) {
            $className = get_class($this->_adapter);

            require_once 'Phpass/Exception/NotSupported.php';
            throw new Phpass_Exception_NotSupported(
                "Adapter '${className}' is not supported on this system."
            );
        }

        $this->_adapter = $adapter;
        return $this;
    }

    /**
     * @param string $password
     * @param string $storedHash
     * @return boolean
     */
    public function checkPassword($password, $storedHash)
    {
        $adapter = $this->getAdapter();

        $hash = $adapter->crypt($password, $storedHash);
        if (!$adapter->isValid($hash)) {
            require_once 'Phpass/Exception/UnexpectedValue.php';
            throw new Phpass_Exception_UnexpectedValue(
                'The adapter returned an invalid value.'
            );
        }

        return $hash == $storedHash;
    }

    /**
     * @param string $password
     * @return string
     */
    public function hashPassword($password)
    {
        $adapter = $this->getAdapter();

        $hash = $adapter->crypt($password);
        if (!$adapter->isValid($hash)) {
            require_once 'Phpass/Exception/UnexpectedValue.php';
            throw new Phpass_Exception_UnexpectedValue(
                'The adapter returned an invalid value.'
            );
        }

        return $hash;
    }

}