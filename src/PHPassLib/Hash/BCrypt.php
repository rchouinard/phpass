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
 * BCrypt Module
 *
 * BCrypt is based on a version of the Blowfish stream cipher, and features
 * a variable number of rounds and a large salt. BCrypt is recommended for
 * new applications.
 *
 * Supported parameters:
 *
 * <ul>
 *   <li><b>rounds:</b> Optional number of rounds to use. Must be an integer
 *   between 4 and 31 inclusive. This value is logarithmic, meaning the actual
 *   number of rounds will be 2^<rounds>. Defaults to 12.</li>
 *
 *   <li><b>ident:</b> Identifier which specifies the version of the algorithm
 *   to use. The default of 2a is correct for most uses, but the following
 *   values are supported: 2a, 2y, 2x. For more information on what these mean,
 *   see http://php.net/security/crypt_blowfish.php.</li>
 *
 *   <li><b>salt:</b> Optional salt string. If provided, it must be a 22
 *   character string containing only characters in the regex range
 *   [./0-9A-Za-z]. It is highly recommended that this parameter be left blank,
 *   in which case the library will generate a suitable salt for you.</li>
 * </ul>
 *
 * This module uses PHP's native crypt() function, which has had native support
 * for BCrypt since 5.3.0. PHP 5.3.7 introduced support for the 2x and 2y
 * identifiers, and applications running on older versions will not be able
 * to use the ident parameter with these values.
 *
 * @package PHPassLib\Hashes
 * @author Ryan Chouinard <rchouinard@gmail.com>
 * @copyright Copyright (c) 2012, Ryan Chouinard
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 */
class BCrypt implements Hash
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
            'ident' => '2a',
            'rounds' => 12,
            'salt' => self::genSalt(),
        );
        $config = array_merge($defaults, array_change_key_case($config, CASE_LOWER));

        $string = '*1';
        if (self::validateOptions($config)) {
            $string = sprintf('$%s$%02d$%s', $config['ident'], (int) $config['rounds'], $config['salt']);
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
        if (preg_match('/^\$(2a|2y|2x)\$(\d{2})\$([\.\/0-9A-Za-z]{22})/', $config, $matches)) {
            $options = array (
                'ident' => $matches[1],
                'rounds' => (int) $matches[2],
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
        $hash = crypt($password, $config);
        if (!preg_match('/^\$(?:2a|2y|2x)\$\d{2}\$[\.\/0-9A-Za-z]{53}$/', $hash)) {
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
     * @param string $input
     * @return string
     */
    protected static function genSalt($input = null)
    {
        if (!$input) {
            $input = Utilities::genRandomBytes(16);
        }
        $count = strlen($input);

        $atoi64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        $output = '';
        $i = 0;
        do {
            $c1 = ord($input[$i++]);
            $output .= $atoi64[$c1 >> 2];
            $c1 = ($c1 & 0x03) << 4;
            if ($i >= $count) {
                $output .= $atoi64[$c1];
                break;
            }

            $c2 = ord($input[$i++]);
            $c1 |= $c2 >> 4;
            $output .= $atoi64[$c1];
            $c1 = ($c2 & 0x0f) << 2;

            $c2 = ord($input[$i++]);
            $c1 |= $c2 >> 6;
            $output .= $atoi64[$c1];
            $output .= $atoi64[$c2 & 0x3f];
        } while (1);

        return $output;
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
                $idents = (version_compare('5.3.7', PHP_VERSION) === 1)
                    ? array ('2a') // <= 5.3.6
                    : array ('2a', '2y', '2x'); // >= 5.3.7
                if (!in_array($value, $idents)) {
                    throw new InvalidArgumentException('Invalid ident parameter');
                }
                break;

            case 'rounds':
                if ($value < 4 || $value > 31) {
                    throw new InvalidArgumentException('Invalid rounds parameter');
                }
                break;

            case 'salt':
                if (!preg_match('/^[\.\/0-9A-Za-z]{22}$/', $value)) {
                    throw new InvalidArgumentException('Invalid salt parameter');
                }
                break;

            default:
                break;

        }

        return true;
    }

}
