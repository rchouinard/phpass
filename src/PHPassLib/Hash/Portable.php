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
 * PHPass Portable Module
 *
 * This module supports Openwall's PHPass Portable Hash format. Information
 * about the original implementation may be found at
 * http://www.openwall.com/phpass/.
 *
 * Supported parameters:
 *
 * <ul>
 *   <li><b>ident:</b> The original implementation uses the identifier P, while
 *   phpBB3 uses H. Defaults to P.</li>
 *
 *   <li><b>rounds:</b> Optional number of rounds to use. Must be an integer
 *   between 7 and 30 inclusive. This value is logarithmic, meaning the actual
 *   number of rounds will be 2^<rounds>. Defaults to 16.</li>
 *
 *   <li><b>salt:</b> Optional salt string. If provided, it must be an 8
 *   character string containing only characters in the regex range
 *   [./0-9A-Za-z]. It is highly recommended that this parameter be left blank,
 *   in which case the library will generate a suitable salt for you.</li>
 * </ul>
 *
 * @package PHPassLib\Hashes
 * @author Ryan Chouinard <rchouinard@gmail.com>
 * @copyright Copyright (c) 2012, Ryan Chouinard
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 */
class Portable implements Hash
{

    const IDENT_PHPASS = 'P';
    const IDENT_PHPBB = 'H';

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
            'ident' => self::IDENT_PHPASS,
            'rounds' => 16,
            'salt' => Utilities::encode64(Utilities::genRandomBytes(6)),
        );
        $config = array_merge($defaults, array_change_key_case($config, CASE_LOWER));

        $string = '*1';
        if (self::validateOptions($config)) {
            $charset = Utilities::CHARS_H64;
            $string = sprintf('$%s$%s%s', $config['ident'], $charset[(int) $config['rounds']], $config['salt']);
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
        if (preg_match('/^\$(P|H)\$([5-9A-S]{1})([\.\/0-9A-Za-z]{8})/', $config, $matches)) {
            $options = array (
                'ident' => $matches[1],
                'rounds' => strpos(Utilities::CHARS_H64, $config[3]),
                'salt' => $matches[3],
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
        $hash = ($config == '*0') ? '*1' : '*0';

        $config = self::parseConfig($config);
        if (is_array($config)) {
            $rounds = (1 << $config['rounds']);
            $checksum = md5($config['salt'] . $password, true);
            do {
                $checksum = md5($checksum . $password, true);
            } while (--$rounds);
            $hash = self::genConfig($config) . Utilities::encode64($checksum);
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

            case 'ident':
                $idents = array (self::IDENT_PHPASS, self::IDENT_PHPBB);
                if (!in_array($value, $idents)) {
                    throw new InvalidArgumentException('Invalid ident parameter');
                }
                break;

            case 'rounds':
                if ($value < 7 || $value > 30) {
                    throw new InvalidArgumentException('Invalid rounds parameter');
                }
                break;

            case 'salt':
                if (!preg_match('/^[\.\/0-9A-Za-z]{8}$/', $value)) {
                    throw new InvalidArgumentException('Invalid salt parameter');
                }
                break;

            default:
                break;

        }

        return true;
    }

}
