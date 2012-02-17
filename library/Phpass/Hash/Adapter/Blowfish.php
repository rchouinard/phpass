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
namespace Phpass\Hash\Adapter;

/**
 * PHPass Bcrypt Hash Adapter
 *
 * @package PHPass
 * @subpackage Hash
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */
class Blowfish extends Base
{

    /**
     * @see \Phpass\Hash\Base::__construct()
     */
    public function __construct(Array $options = array ())
    {
        parent::__construct($options);
        $this->_itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    }

    /**
     * @see \Phpass\Hash\Adapter::genSalt()
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

}