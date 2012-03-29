<?php
/**
 * PHP Password Library
 *
 * @package PHPass\Strength
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */

/**
 * @namespace
 */
namespace Phpass\Strength\Adapter;

/**
 * Strength adapter for NIST recommendations
 *
 * @package PHPass\Strength
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
class Nist extends Base
{

    /**
     * Return the calculated entropy.
     *
     * @param string $password
     *   The string to check.
     * @return integer
     *   Returns the calculated string entropy.
     * @see Adapter::check()
     */
    public function check($password)
    {
        $this->_analyze($password);

        $this->_score = 0;

        // First character is 4 bits of entropy
        if ($this->_length > 0) {
            $this->_score += 4;
        }

        // The next seven characters are 2 bits of entropy
        if ($this->_length > 1) {
            $this->_score += strlen(substr($password, 1, 7)) * 2;
        }

        // Characters 9 through 20 are 1.5 bits of entropy
        if ($this->_length > 8) {
            $this->_score += strlen(substr($password, 8, 12)) * 1.5;
        }

        // Characters 21 and beyond are 1 bit of entropy
        if ($this->_length > 20) {
            $this->_score += strlen(substr($password, 20));
        }

        // Bonus of 6 bits if upper, lower, and non-alpha characters are used
        if ($this->_getClassCount(self::CLASS_UPPER) > 0 && $this->_getClassCount(self::CLASS_LOWER)) {
            if ($this->_getClassCount(self::CLASS_NUMBER) > 0 || $this->_getClassCount(self::CLASS_SYMBOL)) {
                $this->_score += 6;
            }
        }

        return $this->_score;
    }

}