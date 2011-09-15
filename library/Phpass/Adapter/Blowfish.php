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
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */

/**
 * @namespace
 */
namespace Phpass\Adapter;

/**
 * @see Phpass\Adapter\Base
 */
require_once 'Phpass/Adapter/Base.php';

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
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */
class Blowfish extends Base
{

    /**
     * @param array $options
     * @return void
     */
    public function __construct(Array $options = array ())
    {
        parent::__construct($options);
        $this->_itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    }

    /**
     * (non-PHPdoc)
     * @see Phpass\Adapter::genSalt()
     */
    public function genSalt($input = null)
    {
        if (!$input) {
            $input = $this->_getRandomBytes(16);
        }

        // Blowfish requires this number to be between 4 and 31.
        $countLog2 = ($this->_iterationCountLog2 < 4)
            ? 4
            : min($this->_iterationCountLog2, 31);

        $output = '$2a$';
        $output .= chr(ord('0') + $countLog2 / 10);
        $output .= chr(ord('0') + $countLog2 % 10);
        $output .= '$';

        $i = 0;
        do {
            $c1 = ord($input[$i++]);
            $output .= $this->_itoa64[$c1 >> 2];
            $c1 = ($c1 & 0x03) << 4;
            if ($i >= 16) {
                $output .= $this->_itoa64[$c1];
                break;
            }

            $c2 = ord($input[$i++]);
            $c1 |= $c2 >> 4;
            $output .= $this->_itoa64[$c1];
            $c1 = ($c2 & 0x0f) << 2;

            $c2 = ord($input[$i++]);
            $c1 |= $c2 >> 6;
            $output .= $this->_itoa64[$c1];
            $output .= $this->_itoa64[$c2 & 0x3f];
        } while (1);

        return $output;
    }

    /**
     * (non-PHPdoc)
     * @see Phpass\Adapter::isSupported()
     */
    public function isSupported()
    {
        return (bool) CRYPT_BLOWFISH;
    }

    /**
     * (non-PHPdoc)
     * @see Phpass\Adapter::isValid()
     */
    public function isValid($hash)
    {
        $isValid = true;
        if (substr($hash, 0, 4) != '$2a$' || strlen($hash) != 60) {
            $isValid = false;
        }

        return $isValid;
    }

}