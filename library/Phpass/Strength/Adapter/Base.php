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
use Phpass\Strength\Adapter;

/**
 * Strength adapter base class
 *
 * @package PHPass\Strength
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
abstract class Base implements Adapter
{

    const CLASS_LETTER = 'letter';
    const CLASS_UPPER = 'upper';
    const CLASS_LOWER = 'lower';
    const CLASS_NUMBER = 'number';
    const CLASS_SYMBOL = 'symbol';

    /**
     * The string to analyze.
     *
     * @var string
     */
    protected $_password;

    /**
     * The calculated entropy.
     *
     * @var integer
     */
    protected $_score;

    /**
     * The string length in bytes.
     *
     * @var integer
     */
    protected $_length;

    /**
     * Map of the number of times tokens appear in the string.
     *
     * @var array
     */
    protected $_tokens;

    /**
     * Map of indices pointing to token classes in the string.
     *
     * @var array
     */
    protected $_tokenIndices;

    /**
     * Map of the number of times a token class occurs in the string.
     *
     * @var array
     */
    protected $_tokenCounts;

    /**
     * Analyze a string and store relevant metadata.
     *
     * @param string $password
     *   The string to analyze.
     * @return void
     */
    protected function _analyze($password)
    {
        // Reset the class
        $this->_password = $password;
        $this->_score = 0;
        $this->_length = strlen($password);
        $this->_tokens = array ();
        $this->_tokenCounts = array (
            self::CLASS_LETTER => 0,
            self::CLASS_UPPER => 0,
            self::CLASS_LOWER => 0,
            self::CLASS_NUMBER => 0,
            self::CLASS_SYMBOL => 0
        );
        $this->_tokenIndices = array (
            self::CLASS_LETTER => array (),
            self::CLASS_UPPER => array (),
            self::CLASS_LOWER => array (),
            self::CLASS_NUMBER => array (),
            self::CLASS_SYMBOL => array ()
        );

        $this->_parseTokens();
    }

    /**
     * Tokenize the password string.
     *
     * @return void
     */
    protected function _parseTokens()
    {
        for ($index = 0; $index < $this->_length; ++$index) {
            $token = $this->_password[$index];
            $tokenAsciiValue = ord($token);

            if ($tokenAsciiValue >= 48 && $tokenAsciiValue <= 57) {
                $tokenClass = self::CLASS_NUMBER;
            } else if ($tokenAsciiValue >= 65 && $tokenAsciiValue <= 90) {
                $tokenClass = self::CLASS_UPPER;
            } else if ($tokenAsciiValue >= 97 && $tokenAsciiValue <= 122) {
                $tokenClass = self::CLASS_LOWER;
            } else {
                $tokenClass = self::CLASS_SYMBOL;
            }

            // Track the number and index of tokens belonging to class
            ++$this->_tokenCounts[$tokenClass];
            $this->_tokenIndices[$tokenClass][] = $index;

            // Members of UPPER and LOWER also belong to LETTER
            if ($tokenClass == self::CLASS_UPPER || $tokenClass == self::CLASS_LOWER) {
                ++$this->_tokenCounts[self::CLASS_LETTER];
                $this->_tokenIndices[self::CLASS_LETTER][] = $index;
            }

            // Track the number of times this token appears
            if (array_key_exists($token, $this->_tokens)) {
                $this->_tokens[$token] += 1;
            } else {
                $this->_tokens[$token] = 1;
            }
        }
    }

    /**
     * Return a map of token indices within the string for a given class.
     * 
     * @param string $class
     *   Token class to map.
     * @return array
     *   Returns a numerically indexed array of indicies where members of a
     *   given class may be found in the string.
     */
    protected function _getClassIndices($class)
    {
        $indices = array ();
        if ($class == self::CLASS_LETTER) {
            $indices = array_merge(
                $this->_getClassIndices(self::CLASS_LOWER),
                $this->_getClassIndices(self::CLASS_UPPER)
            );
            sort($indices);
        } else {
            if (isset ($this->_tokenIndices[$class])) {
                $indices = $this->_tokenIndices[$class];
            }
        }
        return $indices;
    }

    /**
     * Return the number of times members of a token class appear in the string.
     *
     * @param string $class
     *   Token class to count.
     * @return integer
     *   Returns the number of times members of the token class appear in the
     *   string.
     */
    protected function _getClassCount($class)
    {
        $count = 0;
        if ($class == self::CLASS_LETTER) {
            $count = $this->_getClassCount(self::CLASS_LOWER)
                   + $this->_getClassCount(self::CLASS_UPPER);
        } else {
            if (isset ($this->_tokenCounts[$class])) {
                $count = $this->_tokenCounts[$class];
            }
        }
        return $count;
    }

}