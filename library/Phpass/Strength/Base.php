<?php
/**
 * Portable PHP password hashing framework.
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
namespace Phpass\Strength;
use Phpass\Strength;

/**
 * @see Phpass\Strength
 */
require_once 'Phpass/Strength.php';

/**
 * Portable PHP password hashing framework.
 *
 * @package PHPass
 * @subpackage Strength
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */
abstract class Base implements Strength
{

    const CLASS_LETTER = 'letter';
    const CLASS_UPPER = 'upper';
    const CLASS_LOWER = 'lower';
    const CLASS_NUMBER = 'number';
    const CLASS_SYMBOL = 'symbol';

    /**
     * Password string to analyze.
     *
     * @var string
     */
    protected $_password;

    /**
     * Calculated strength score.
     *
     * @var integer
     */
    protected $_score;

    /**
     * Password string length in bytes.
     *
     * @var integer
     */
    protected $_length;

    /**
     * Map of the number of times tokens appear in the password string.
     *
     * @var array
     */
    protected $_tokens;

    /**
     * Map of indices pointing to token class in the password string.
     *
     * @var array
     */
    protected $_tokenIndices;

    /**
     * Map of the number of times a token class occurs in the password string.
     *
     * @var array
     */
    protected $_tokenCounts;

    /**
     * Analyze a password string and store relevant metadata.
     *
     * @param string $password
     *   The password string to analyze.
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

            // Members of UPPER and LOWER also belong to LETTER...
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
     * Get an array of token indices within the password string for a given
     * class.
     *
     * @param string $class
     *   Token class to retrieve indices for.
     * @return array
     */
    protected function _getClassIndices($class)
    {
        $indices = array ();
        if (isset ($this->_tokenIndices[$class])) {
            $indices = $this->_tokenIndices[$class];
        }
        return $indices;
    }

    /**
     * Get a token count within the password string for a given class.
     *
     * @param string $class
     *   Token class to retrieve count for.
     * @return integer
     */
    protected function _getClassCount($class)
    {
        $count = 0;
        if (isset ($this->_tokenCounts[$class])) {
            $count = $this->_tokenCounts[$class];
        }
        return $count;
    }

}