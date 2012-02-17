<?php
/**
 * PHP Password Library
 *
 * @package PHPass
 * @subpackage Strength
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */

/**
 * @namespace
 */
namespace Phpass;
use Phpass\Strength\Adapter,
    Phpass\Strength\Adapter\Nist,
    Phpass\Exception\InvalidArgumentException;

/**
 * PHPass Strength Class
 *
 * @package PHPass
 * @subpackage Strength
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */
class Strength
{

    /**
     * Instance of the adapter to use for calculating password strength.
     *
     * @var \Phpass\Strength\Adapter
     */
    protected $_adapter;

    /**
     * Class constructor.
     *
     * @param array|\Phpass\Strength\Adapter $options
     *   Either an associative array of options, or an instance of
     *   \Phpass\Strength\Adapter.
     * @return void
     */
    public function __construct($options = array ())
    {
        // Default adapter
        $this->_adapter = new Nist;

        if ($options instanceof Adapter) {
            $options = array (
                'adapter' => $options
            );
        }

        if (!is_array($options)) {
            throw new InvalidArgumentException('Expected either an array, or an instance of Phpass\\Strength\\Adapter.');
        }

        $this->setOptions($options);
    }

    /**
     * Set the adapter to use for calculating password strength.
     *
     * @param \Phpass\Strength\Adapter $adapter
     *   An instance of \Phpass\Strength\Adapter.
     * @return \Phpass\Strength
     */
    public function setAdapter(Adapter $adapter)
    {
        $this->_adapter = $adapter;
        return $this;
    }

    /**
     * Retrieve the adapter used for calculating password strength.
     *
     * @return \Phpass\Strength\Adapter
     */
    public function getAdapter()
    {
        return $this->_adapter;
    }

    /**
     * Set instance options.
     *
     * Available options:
     *   - adapter: An instance of Phpass\Strength\Adapter.
     *
     * @param array $options
     *   An associative array of options.
     * @return \Phpass\Strength
     */
    public function setOptions(Array $options)
    {
        $options = array_change_key_case($options, CASE_LOWER);
        foreach ($options as $option => $value) {
            switch ($option) {
                case 'adapter':
                    if (!$value instanceof Adapter) {
                        throw new InvalidArgumentException("Value of key 'adapter' must be an instance of Phpass\\Strength\\Adapter.");
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
     * Calculate the strength of the given password.
     *
     * @param string $password
     *   The password string to check.
     * @return integer
     *   Returns the calculated password entropy.
     */
    public function calculate($password)
    {
        return $this->_adapter->check($password);
    }

}