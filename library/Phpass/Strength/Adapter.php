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
namespace Phpass\Strength;

/**
 * Strength adapter interface
 *
 * @package PHPass\Strength
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
interface Adapter
{

    /**
     * Return the calculated entropy.
     *
     * @param string $password
     *   The string to check.
     * @return integer
     *   Returns the calculated string entropy.
     */
    public function check($password);

}