<?php
/**
 * PHP Password Library
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
namespace Phpass\Strength\Adapter;

/**
 * PHP Password Library
 *
 * @package PHPass
 * @subpackage Strength
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */
class Wolfram extends Base
{

    /**
     * @see Phpass\Strength\Adapter::check()
     */
    public function check($password)
    {
        $this->_analyze($password);

        $this->_score  = $this->_calculateBaseScore();
        $this->_score += $this->_calculateLetterScore();
        $this->_score += $this->_calculateNumberScore();
        $this->_score += $this->_calculateSymbolScore();
        $this->_score += $this->_calculateMiddleNumberOrSymbolScore();

        if ($this->_getClassCount(self::CLASS_LETTER) == $this->_length || $this->_getClassCount(self::CLASS_NUMBER) == $this->_length) {
            $this->_score -= $this->_length;
        }

        $this->_score += $this->_calculateRepeatTokenScore();

        if ($this->_length > 2) {
            $this->_score += $this->_calculateConsecutiveTokenScore(self::CLASS_UPPER);
            $this->_score += $this->_calculateConsecutiveTokenScore(self::CLASS_LOWER);
            $this->_score += $this->_calculateConsecutiveTokenScore(self::CLASS_NUMBER);

            $this->_score += $this->_calculateSequentialTokenScore(self::CLASS_LETTER);
            $this->_score += $this->_calculateSequentialTokenScore(self::CLASS_NUMBER);
        }

        return $this->_score;
    }

    /**
     * Calculate the base score based on string length.
     *
     * @return integer
     */
    protected function _calculateBaseScore()
    {
        return $this->_length * 4;
    }

    /**
     * Calculate a score for letter tokens.
     *
     * @return integer
     */
    protected function _calculateLetterScore()
    {
        $score = 0;

        foreach (array (self::CLASS_UPPER, self::CLASS_LOWER) as $class) {
            $letterCount = $this->_getClassCount($class);

            if ($letterCount != $this->_length) {
                if ($letterCount > 0) {
                    $score += ($this->_length - $letterCount) * 2;
                }
            }
        }

        return $score;
    }

    /**
     * Calculate a score for number tokens.
     *
     * @return integer
     */
    protected function _calculateNumberScore()
    {
        $score = 0;
        $numberCount = $this->_getClassCount(self::CLASS_NUMBER);

        if ($numberCount > 0 && $numberCount != $this->_length) {
            $score += $numberCount * 4;
        }

        return $score;
    }

    /**
     * Calculate a score for symbol tokens.
     *
     * @return integer
     */
    protected function _calculateSymbolScore()
    {
        $score = 0;
        $symbolCount = $this->_getClassCount(self::CLASS_SYMBOL);

        if ($symbolCount > 0) {
            $score += $symbolCount * 4;
        }

        return $score;
    }

    /**
     * Calculate a score for special tokens in the middle of the string.
     *
     * @return integer
     */
    protected function _calculateMiddleNumberOrSymbolScore()
    {
        $score = 0;

        foreach (array (self::CLASS_NUMBER, self::CLASS_SYMBOL) as $class) {
            $indices = $this->_getClassIndices($class);
            foreach (array (0, $this->_length - 1) as $index) {
                if (array_search($index, $indices)) {
                    unset ($indicies[array_search($index, $indices)]);
                }
            }
            $score += count($indices) * 2;
        }

        return $score;
    }

    /**
     * Calculate a score for repeated characters.
     *
     * @return integer
     */
    protected function _calculateRepeatTokenScore()
    {
        $score = 0;
        $repeats = 0;

        foreach ($this->_tokens as $token => $tokenCount) {
            if ($tokenCount > 1) {
                $repeats += $tokenCount - 1;
            }
        }

        if ($repeats > 0) {
            $score -= (int) ($repeats / ($this->_length - $repeats)) + 1;
        }

        return $score;
    }

    /**
     * Calculate a score for consectutive tokens of the same class.
     *
     * @param string $class
     *   The token class to check.
     * @return integer
     */
    protected function _calculateConsecutiveTokenScore($class)
    {
        $score = 0;
        $pattern = '/[^a-zA-Z0-9]{2,}/';

        if ($class == self::CLASS_LETTER) {
            $pattern = '/[a-zA-Z]{2,}/';
        }

        if ($class == self::CLASS_UPPER) {
            $pattern = '/[A-Z]{2,}/';
        }

        if ($class == self::CLASS_LOWER) {
            $pattern = '/[a-z]{2,}/';
        }

        if ($class == self::CLASS_NUMBER) {
            $pattern = '/[0-9]{2,}/';
        }

        $matches = array ();
        preg_match_all($pattern, $this->_password, $matches);
        foreach ($matches[0] as $match) {
            $score -= (strlen($match) - 1) * 2;
        }

        return $score;
    }

    /**
     * Calculate a score for sequential tokens of the same class.
     *
     * @param string $class
     *   The token class to check.
     * @return integer
     */
    protected function _calculateSequentialTokenScore($class)
    {
        $score = 0;
        $indices = array ();
        $password = $this->_password;
        $sequences = array ();

        if ($class == self::CLASS_LETTER) {
            $indices = array_merge(
                $this->_getClassIndices(self::CLASS_LOWER),
                $this->_getClassIndices(self::CLASS_UPPER)
            );
            $password = strtolower($password);
        } else {
            $indices = $this->_getClassIndices($class);
        }

        sort($indices);

        $sequence = '';
        for ($index = 0; $index < count($indices); ++$index) {
            if (!isset ($indices[$index + 1])) {
                continue;
            }

            if ($indices[$index + 1] - $indices[$index] == 1 && ord($password[$indices[$index + 1]]) - ord($password[$indices[$index]]) == 1) {
                if ($sequence == '') {
                    $sequence = $password[$indices[$index]] . $password[$indices[$index + 1]];
                } else {
                    $sequence .= $password[$indices[$index + 1]];
                }
            } else {
                if ($sequence != '') {
                    $sequences[] = $sequence;
                    $sequence = '';
                }
            }
        }

        foreach ($sequences as $sequence) {
            if (strlen($sequence) > 2) {
                $score -= (strlen($sequence) - 2) *2;
            }
        }

        return $score;
    }

}