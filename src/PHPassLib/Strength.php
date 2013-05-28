<?php
/**
 * PHP Password Library
 *
 * @package PHPassLib\Strength
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */

namespace PHPassLib;

use PHPassLib\Exception\InvalidArgumentException;
use PHPassLib\Strength\Adapter;
use PHPassLib\Strength\Adapter\Nist;

/**
 * Strength class
 *
 * Provides a simple API for working with the various strength calculator
 * adapters. If the class is constructed with no arguments, it will construct
 * an NIST adapter with default settings for use internally.
 *
 *     <?php
 *     $phpassStrength = new \PHPassLib\Strength;
 *
 *     // Calculate password string entropy
 *     $passwordStrength = $phpassStrength->calculate($password);
 *
 * @package PHPassLib\Strength
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
class Strength
{

    /**
     * Instance of the adapter to use for calculating string entropy.
     *
     * @var \PHPassLib\Strength\Adapter
     */
    protected $_adapter;

    /**
     * Class constructor.
     *
     *     <?php
     *     // Just use the default NIST adapter
     *     $phpassStrength = new \PHPassLib\Strength;
     *
     *     // Customize the adapter
     *     $adapter = new \PHPassLib\Strength\Adapter\Wolfram;
     *     $phpassStrength = new \PHPassLib\Strength($adapter);
     *
     *     // Customize the adapter via options array
     *     $options = array (
     *         'adapter' => new \PHPassLib\Strength\Adapter\Wolfram
     *     );
     *     $phpassStrength = new \PHPassLib\Strength($options);
     *
     * @param Array|\PHPassLib\Strength\Adapter $options
     *   Either an associative array of options, or an instance of Adapter.
     * @return void
     * @throws \PHPassLib\Exception\InvalidArgumentException
     *   An InvalidArgumentException is thrown if a value other than an Adapter
     *   instance or options array is passed to the constructor.
     */
    public function __construct($options = array ())
    {
        $this->_adapter = new Nist;
        if ($options instanceof Adapter) {
            $options = array ('adapter' => $options);
        }

        if (!is_array($options)) {
            throw new InvalidArgumentException('Expected an instance of PHPassLib\\Strength\\Adapter or an associative array of options.');
        }

        $this->setOptions($options);
    }

    /**
     * Set the adapter to use for calculating string entropy.
     *
     * @param \PHPassLib\Strength\Adapter $adapter
     *   An instance of a class implementing the Adapter interface.
     * @return Strength
     */
    public function setAdapter(Strength\Adapter $adapter)
    {
        $this->_adapter = $adapter;

        return $this;
    }

    /**
     * Retrieve the adapter used for calculating string entropy.
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
     * </dl>
     *
     * @param Array $options
     *   An associative array of options.
     * @return Strength
     * @throws InvalidArgumentException
     *   An InvalidArgumentException is thrown if a value does not match what
     *   is expected for the option key.
     */
    public function setOptions(Array $options)
    {
        $options = array_change_key_case($options, CASE_LOWER);
        foreach ($options as $option => $value) {
            switch ($option) {
                case 'adapter':
                    if (!$value instanceof Adapter) {
                        throw new InvalidArgumentException("Value of key 'adapter' must be an instance of PHPassLib\\Strength\\Adapter.");
                    }
                    $this->setAdapter($value);
                    break;
                default:
                    break;
            }
        }

        return $this;
    }

    /**
     * Return the calculated entropy.
     *
     * @param string $password
     *   The string to check.
     * @return integer
     *   Returns the calculated string entropy.
     */
    public function calculate($password)
    {
        return $this->_adapter->check($password);
    }

}
