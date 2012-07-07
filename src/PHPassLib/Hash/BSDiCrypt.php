<?php
/**
 * PHP Password Library
 *
 * @package PHPassLib\Hashes
 * @author Ryan Chouinard <rchouinard@gmail.com>
 * @copyright Copyright (c) 2012, Ryan Chouinard
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 * @version 3.0.0-dev
 */

namespace PHPassLib\Hash;
use PHPassLib\Hash,
    PHPassLib\Utilities,
    PHPassLib\Exception\InvalidArgumentException;

/**
 * BSDi / Extended DES Crypt Module
 *
 * Also known as extended DES, BSDi Crypt is based on DES Crypt but adds a
 * configurable number of rounds and a larger salt. The algorithm is considered
 * weak by modern standards and should not be used for new applications. It is
 * only provided here for completeness.
 *
 *<code>
 * <?php
 * use PHPassLib\Hash\BSDiCrypt;
 *
 * $hash = BSDiCrypt::hash($password);
 * if (BSDiCrypt::verify($password, $hash)) {
 *     // Password matches, user is authenticated
 * }
 * </code>
 *
 */
class BSDiCrypt implements Hash
{

    /**
     * Generate a config string suitable for use with module hashes.
     *
     * Available options:
     *  - rounds: Must be between 1 and 16777215. Defaults to 5001.
     *  - salt: If provided, must be a 2-character string containing only
     *      characters from ./0-9A-Za-z. It is recommended to omit this option
     *      and let the class generate one for you.
     *
     * @param array $config Array of configuration options.
     * @return string Configuration string in the format
     *     "_<rounds><salt><checksum>".
     * @throws InvalidArgumentException Throws an InvalidArgumentException if
     *     any passed-in configuration options are invalid.
     */
    public static function genConfig(Array $config = array ())
    {
        $defaults = array (
            'rounds' => 5001,
            'salt' => Utilities::encode64(Utilities::genRandomBytes(3)),
        );
        $config = array_merge($defaults, array_change_key_case($config, CASE_LOWER));

        $string = '*1';
        if (self::validateOptions($config)) {
            // Rounds needs to be odd in order to avoid exposing wek DES keys
            if (($config['rounds'] % 2) == 0) {
                --$config['rounds'];
            }

            $string = sprintf('_%s%s', Utilities::encodeInt24($config['rounds']), $config['salt']);
        }

        return $string;
    }

    /**
     * Generate a hash using a pre-defined config string.
     *
     * @param string $password Password string.
     * @param string $config Configuration string.
     * @return string Returns the hash string on success. On failure, one of
     *     *0 or *1 is returned.
     */
    public static function genHash($password, $config)
    {
        $hash = crypt($password, $config);
        if (!preg_match('/^_[\.\/0-9A-Za-z]{19}$/', $hash)) {
            $hash = ($config == '*0') ? '*1' : '*0';
        }

        return $hash;
    }

    /**
     * Generate a hash using either a pre-defined config string or an array.
     *
     * @param string $password Password string.
     * @param string|array $config Optional config string or array of options.
     * @return string Encoded password hash.
     */
    public static function hash($password, $config = array ())
    {
        if (is_array($config)) {
            $config = self::genConfig($config);
        }

        return self::genHash($password, $config);
    }

    /**
     * Verify a password against a hash string.
     *
     * @param string $password Password string.
     * @param string $hash Hash string.
     * @return boolean Returns true if the password matches, false otherwise.
     */
    public static function verify($password, $hash)
    {
        return ($hash === self::hash($password, $hash));
    }

    /**
     * Validate a set of module options.
     *
     * @param array $options Associative array of options.
     * @return boolean Returns true if all options are valid.
     * @throws InvalidArgumentException Throws an InvalidArgumentException
     *     if an invalid option value is encountered.
     */
    protected static function validateOptions(Array $options)
    {
        $options = array_change_key_case($options, CASE_LOWER);
        foreach ($options as $option => $value) switch ($option) {

            case 'rounds':
                if ($value < 0 || $value > 0xffffff) {
                    throw new InvalidArgumentException('Rounds must be in the range 1 - 16777215.');
                }
                break;

            case 'salt':
                if (!preg_match('/^[\.\/0-9A-Za-z]{4}$/', $value)) {
                    throw new InvalidArgumentException('Salt must be a string matching the regex pattern /[./0-9A-Za-z]{4}/.');
                }
                break;

            default:
                break;

        }

        return true;
    }

}