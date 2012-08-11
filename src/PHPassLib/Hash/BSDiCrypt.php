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

use PHPassLib\Hash;
use PHPassLib\Utilities;
use PHPassLib\Exception\InvalidArgumentException;

/**
 * BSDi / Extended DES Crypt Module
 *
 * BSDi Crypt is based on DES Crypt, and was developed by BSDi for their BSD/OS
 * distribution. The algorithm is also commonly known as <i>Extended DES</i>.
 *
 * Supported parameters:
 *
 * <ul>
 *   <li><b>rounds:</b> Optional number of rounds to use. Must be an integer
 *   between 1 and 16777215 inclusive. Even rounds values will be decreased
 *   by one to create an odd number in order to prevent exposing weak keys.
 *   Defaults to 5001.</li>
 *
 *   <li><b>salt:</b> Optional salt string. If provided, it must be a 4
 *   character string containing only characters in the regex range
 *   [./0-9A-Za-z]. It is highly recommended that this parameter be left blank,
 *   in which case the library will generate a suitable salt for you.</li>
 * </ul>
 *
 * This module uses PHP's native crypt() function, which has had native support
 * for BSDi Crypt since 5.3.0.
 *
 * @package PHPassLib\Hashes
 * @author Ryan Chouinard <rchouinard@gmail.com>
 * @copyright Copyright (c) 2012, Ryan Chouinard
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 */
class BSDiCrypt implements Hash
{

    /**
     * Generate a config string from an array.
     *
     * @param array $config Array of configuration options.
     * @return string Configuration string.
     * @throws InvalidArgumentException Throws an InvalidArgumentException if
     *     any passed-in configuration options are invalid.
     */
    public static function genConfig(array $config = array ())
    {
        $defaults = array (
            'rounds' => 5001,
            'salt' => Utilities::encode64(Utilities::genRandomBytes(3)),
        );
        $config = array_merge($defaults, array_change_key_case($config, CASE_LOWER));

        $string = '*1';
        if (self::validateOptions($config)) {
            // Rounds needs to be odd in order to avoid exposing weak DES keys
            if (($config['rounds'] % 2) == 0) {
                --$config['rounds'];
            }

            $string = sprintf('_%s%s', Utilities::encodeInt24($config['rounds']), $config['salt']);
        }
        return $string;
    }

    /**
     * Parse a config string into an array.
     *
     * @param string $config Configuration string.
     * @return array Array of configuration options or false on failure.
     */
    public static function parseConfig($config)
    {
        $options = false;
        $matches = array ();
        if (preg_match('/^_([\.\/0-9A-Za-z]{4})([\.\/0-9A-Za-z]{4})/', $config, $matches)) {
            $options = array (
                'rounds' => (int) Utilities::decodeInt24($matches[1]),
                'salt' => $matches[2],
            );

            try {
                self::validateOptions($options);
            } catch (InvalidArgumentException $e) {
                $options = false;
            }
        }

        return $options;
    }

    /**
     * Generate a password hash using a config string.
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
     * Generate a password hash using a config string or array.
     *
     * @param string $password Password string.
     * @param string|array $config Optional config string or array of options.
     * @return string Returns the hash string on success. On failure, one of
     *     *0 or *1 is returned.
     * @throws InvalidArgumentException Throws an InvalidArgumentException if
     *     any passed-in configuration options are invalid.
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
     * @param array $options
     * @return boolean
     * @throws InvalidArgumentException
     */
    protected static function validateOptions(array $options)
    {
        $options = array_change_key_case($options, CASE_LOWER);
        foreach ($options as $option => $value) switch ($option) {

            case 'rounds':
                if ($value < 1 || $value > 0xffffff) {
                    throw new InvalidArgumentException('Invalid rounds parameter');
                }
                break;

            case 'salt':
                if (!preg_match('/^[\.\/0-9A-Za-z]{4}$/', $value)) {
                    throw new InvalidArgumentException('Invalid salt parameter');
                }
                break;

            default:
                break;

        }

        return true;
    }

}
