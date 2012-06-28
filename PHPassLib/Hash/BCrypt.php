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
 *
 */
class BCrypt implements Hash
{

    /**
     * Generate a config string suitable for use with bcrypt hashes.
     *
     * Available options:
     *  - ident: Hash identifier to use. PHP versions <5.3.8 must use 2a,
     *      while versions >=5.3.8 may use 2a, 2y, or 2x. Defaults to 2a.
     *  - rounds: Cost parameter which will be encoded as a zero-padded
     *      two-digit number. This value is logarithmic, so the number of
     *      iterations will be determined as 2^<rounds>. Must be between 4 and
     *      31, defaults to 12.
     *  - salt: If provided, must be a 22-character string containing only
     *      characters from ./0-9A-Za-z. It is recommended to omit this option
     *      and let the class generate one for you.
     *
     * @param array $config Array of configuration options.
     * @return string Configuration string in the format
     *     "$<ident>$<rounds>$<salt>".
     * @throws InvalidArgumentException Throws an InvalidArgumentException if
     *     any passed-in configuration options are invalid.
     */
    public static function genConfig(Array $config = array ())
    {
        $defaults = array (
            'ident' => '2a',
            'rounds' => 12,
            'salt' => static::genSalt(),
        );
        $config = array_merge($defaults, array_change_key_case($config, CASE_LOWER));

        if (static::validateOptions($config)) {
            return sprintf('$%s$%02d$%s', $config['ident'], (int) $config['rounds'], $config['salt']);
        } else {
            return '*1';
        }
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
        if (!preg_match('/^\$(?:2a|2y|2x)\$\d{2}\$[\.\/0-9A-Za-z]{53}$/', $hash)) {
            $hash = ($config == '*0') ? '*1' : '*0';
        }

        return $hash;
    }

    /**
     * Generate a hash using either a pre-defined config string or an array.
     *
     * @see genConfig()
     * @see genHash()
     * @param string $password Password string.
     * @param string|array $config Optional config string or array of options.
     * @return string
     */
    public static function hash($password, $config = array ())
    {
        if (is_array($config)) {
            $config = static::genConfig($config);
        }

        return static::genHash($password, $config);
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
        return ($hash === static::hash($password, $hash));
    }

    /**
     * Generate a valid salt string.
     *
     * @param string $input Optional random string of raw bytes.
     * @return string Encoded salt string.
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

            // Ident must be one of 2a, 2y, or 2x. If PHP version is < 5.3.7,
            // only 2a is valid.
            case 'ident':
                $idents = (version_compare('5.3.7', PHP_VERSION) === 1)
                ? array ('2a') // < 5.3.7
                : array ('2a', '2y', '2x'); // >= 5.3.7
                if (!in_array($value, $idents)) {
                    throw new InvalidArgumentException("Ident parameter must be one of 2a, 2y, or 2x. A value of \"$value\" was given.");
                }
                break;

            // Rounds must be between 4 and 31.
            case 'rounds':
                if ($value < 4 || $value > 31) {
                    throw new InvalidArgumentException("Rounds parameter must be a number between 4 and 31 inclusive. A value of \"$value\" was given.");
                }
                break;

            // Any salt must be 22 characters in length and contain only
            // characters in the range [./0-9A-Za-z].
            case 'salt':
                if (!preg_match('/^[\.\/0-9A-Za-z]{22}$/', $value)) {
                    throw new InvalidArgumentException("Salt parameter must be a 22 character string containing only characters in the range ./0-9A-Za-z.");
                }
                break;

            default:
                break;

        }

        return true;
    }

}