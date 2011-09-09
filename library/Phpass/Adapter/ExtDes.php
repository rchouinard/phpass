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

/**
 * @namespace
 */
namespace Phpass\Adapter;

/**
 * @see \Phpass\Adapter
 */
require_once 'Phpass/Adapter.php';

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
class ExtDes extends \Phpass\Adapter
{

    /**
     * (non-PHPdoc)
     * @see Phpass_AdapterInterface::genSalt()
     */
    public function genSalt($input = null)
    {
        if (!$input) {
            $input = $this->_getRandomBytes(3);
        }

        $countLog2 = min($this->_iterationCountLog2 + 8, 24);
        // This should be odd to not reveal weak DES keys, and the
        // maximum valid value is (2**24 - 1) which is odd anyway.
        $count = (1 << $countLog2) - 1;

        $output = '_';
        $output .= $this->_itoa64[$count & 0x3f];
        $output .= $this->_itoa64[($count >> 6) & 0x3f];
        $output .= $this->_itoa64[($count >> 12) & 0x3f];
        $output .= $this->_itoa64[($count >> 18) & 0x3f];

        $output .= $this->_encode64($input, 3);

        return $output;
    }

    /**
     * (non-PHPdoc)
     * @see Phpass_AdapterInterface::isSupported()
     */
    public function isSupported()
    {
        return (bool) CRYPT_EXT_DES;
    }

    /**
     * (non-PHPdoc)
     * @see Phpass_AdapterInterface::isValid()
     */
    public function isValid($hash)
    {
        $isValid = true;
        if (substr($hash, 0, 1) != '_' || strlen($hash) != 20) {
            $isValid = false;
        }

        return $isValid;
    }

}