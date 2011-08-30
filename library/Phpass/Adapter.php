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
 * @version 0.4
 */

require_once 'Phpass/AdapterInterface.php';

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
 * @version 0.4
 */
abstract class Phpass_Adapter implements Phpass_AdapterInterface
{

    /**
     * @var string
     */
    protected $_itoa64;

    /**
     * @var integer
     */
    protected $_iterationCountLog2;

    /**
     * @param array $options
     * @return void
     */
    public function __construct(Array $options = array ())
    {
        $this->_itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        $this->_iterationCountLog2 = 8;

        $this->setOptions($options);
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
                    $iterationCountLog2 = (int) $value;
                    if ($iterationCountLog2 < 4 || $iterationCountLog2 > 31) {
                        throw new InvalidArgumentException(
                            "Value of 'iterationCountLog2' is invalid. " .
                            "Expected integer in range 4-31. Value of " .
                            "'${value}' given."
                        );
                    }
                    $this->_iterationCountLog2 = $iterationCountLog2;
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
     * (non-PHPdoc)
     * @see Phpass_AdapterInterface::crypt()
     */
    public function crypt($password, $salt)
    {
        return crypt($password, $salt);
    }

}