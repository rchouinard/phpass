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
 * PHPass Extended DES Hash Adapter
 *
 * @package PHPass
 * @subpackage Hash
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */
class ExtDes extends Base
{

    /**
     * @see \Phpass\Hash\Adapter::genSalt()
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

}