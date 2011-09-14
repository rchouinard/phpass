<?php
/**
 * Portable PHP password hashing framework.
 *
 * @package PHPass
 * @subpackage Adapters
 * @category Cryptography
 * @author Solar Designer <solar at openwall.com>
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license Public Domain
 * @link http://www.openwall.com/phpass/ Original phpass project page.
 * @version 0.5
 */

/**
 * @namespace
 */
namespace Phpass\Adapter;
use Phpass\Adapter,
    Phpass\Exception\InvalidArgumentException,
    Phpass\Exception\RuntimeException;

/**
 * @see Phpass\Adapter
 */
require_once 'Phpass/Adapter.php';

/**
 * @see Phpass\Exception\InvalidArgumentException
 */
require_once 'Phpass/Exception/InvalidArgumentException.php';

/**
 * @see Phpass\Exception\RuntimeException
 */
require_once 'Phpass/Exception/RuntimeException.php';

/**
 * Portable PHP password hashing framework.
 *
 * @package PHPass
 * @subpackage Adapters
 * @category Cryptography
 * @author Solar Designer <solar at openwall.com>
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license Public Domain
 * @link http://www.openwall.com/phpass/ Original phpass project page.
 * @version 0.5
 */
abstract class Base implements Adapter
{

    /**
     * @var integer
     */
    protected $_iterationCountLog2;

    /**
     * @var string
     */
    protected $_itoa64;

    /**
     * @var string
     */
    protected $_randomState;


    /**
     * @param array $options
     * @return void
     */
    public function __construct(Array $options = array ())
    {
        $this->_itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        $this->_iterationCountLog2 = 8;

        $this->_randomState = microtime();
        if (function_exists('getmypid')) {
            $this->_randomState .= getmypid();
        }

        $this->setOptions($options);
    }

    /**
     * (non-PHPdoc)
     * @see Phpass\Adapter::crypt()
     */
    public function crypt($password, $salt = null)
    {
        if (!$salt) {
            $salt = $this->genSalt();
        }
        return crypt($password, $salt);
    }

    /**
     * @param array $options
     * @return void
     */
    public function setOptions(Array $options)
    {
        $options = array_change_key_case($options, CASE_LOWER);

        foreach ($options as $key => $value) {
            switch ($key) {

                case 'iterationcountlog2':
                    $this->_iterationCountLog2 = (int) $value;
                    break;

                default:
                    break;

            }
        }
    }

    /**
     * @param string $input
     * @param integer $count
     */
    protected function _encode64($input, $count)
    {
        $output = '';
        $i = 0;
        do {
            $value = ord($input[$i++]);
            $output .= $this->_itoa64[$value & 0x3f];
            if ($i < $count) {
                $value |= ord($input[$i]) << 8;
            }
            $output .= $this->_itoa64[($value >> 6) & 0x3f];
            if ($i++ >= $count) {
                break;
            }
            if ($i < $count) {
                $value |= ord($input[$i]) << 16;
            }
            $output .= $this->_itoa64[($value >> 12) & 0x3f];
            if ($i++ >= $count) {
                break;
            }
            $output .= $this->_itoa64[($value >> 18) & 0x3f];
        } while ($i < $count);

        return $output;
    }

    /**
     * @param integer $count
     * @return string
     */
    protected function _getRandomBytes($count)
    {
        $output = '';
        if (is_readable('/dev/urandom') && ($fh = @fopen('/dev/urandom', 'rb'))) {
            $output = fread($fh, $count);
            fclose($fh);
        }

        if (strlen($output) < $count) {
            $output = '';
            for ($i = 0; $i < $count; $i += 16) {
                $this->_randomState = md5(microtime() . $this->_randomState);
                $output .= md5($this->_randomState, true);
            }
            $output = substr($output, 0, $count);
        }

        return $output;
    }

    /**
     * @param string $adapter
     * @param array $options
     * @return Phpass\Adapter
     * @throws Phpass\Exception\InvalidArgumentException
     */
    static public function factory($adapter, Array $options = array ())
    {
        if (!is_string($adapter)) {
            throw new InvalidArgumentException(
                'Required argument $adapter is expected to be a string containing the name of an adapter'
            );
        }

        // Map adapter aliases to class names
        if (strtolower($adapter) == 'blowfish') {
            $adapter = 'Phpass\Adapter\Blowfish';
        } else if (strtolower($adapter) == 'extdes') {
            $adapter = 'Phpass\Adapter\ExtDes';
        } else if (strtolower($adapter) == 'portable') {
            $adapter = 'Phpass\Adapter\Portable';
        }

        // Attempt to include file based on adapter class name
        if (!class_exists($adapter, false)) {
            // Work with My_Adapter or My\Adapter
            $file = trim(str_replace(array ('\\', '_'), DIRECTORY_SEPARATOR, $adapter), DIRECTORY_SEPARATOR);
            @include $file . '.php';
        }

        // Create an instance of the adapter if it exists and implements Adapter
        if (class_exists($adapter, false) && in_array('Phpass\Adapter', class_implements($adapter, false))) {
            $instance = new $adapter($options);
            return $instance;
        }

        throw new RuntimeException(
            "Failed loading adapter '${adapter}'"
        );
    }

}