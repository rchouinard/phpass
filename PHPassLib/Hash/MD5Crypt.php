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
class MD5Crypt implements Hash
{

    /**
     * Generate a config string suitable for use with MD5 crypt hashes.
     *
     * Available options:
     *  - salt: Salt string which must be between 0 and 8 characters
     *      in length, using characters in the range ./0-9A-Za-z. If none is
     *      given, a valid salt value will be generated.
     *
     * @param array $config Array of configuration options
     * @return string Configuration string in the format
     *     $1$<salt>$
     * @throws InvalidArgumentException Throws an InvalidArgumentException if
     *     any passed-in configuration options are invalid
     */
    public static function genConfig(Array $config = array ())
    {
        $defaults = array (
            'salt' => null,
        );
        $config = array_merge($defaults, array_change_key_case($config, CASE_LOWER));

        // Validate or generate a new salt value
        if ($config['salt'] === null || $config['salt'] === false) {
            $config['salt'] = Utilities::encode64($input ?: Utilities::genRandomBytes(6));
        }

        if ($config['salt'] && !preg_match('/^[\.\/0-9A-Za-z]+$/', $config['salt'])) {
            throw new InvalidArgumentException('Salt must be a string containing only the characters ./0-9A-Za-z');
        }

        return sprintf('$1$%s$', $config['salt']);
    }

    /**
     * Generate a hash using a pre-defined config string.
     *
     * @param string $password
     * @param string $config
     * @return string
     */
    public static function genHash($password, $config)
    {
        $hash = crypt($password, $config);
        if (!preg_match('/^\$1\$[\.\/0-9A-Za-z]{0,8}\$[\.\/0-9A-Za-z]{22}$/', $hash)) {
            $hash = ($config == '*0') ? '*1' : '*0';
        }

        return $hash;
    }

    /**
     * Generate a hash using either a pre-defined config string or an array.
     *
     * @see BCrypt::genConfig()
     * @param string $password
     * @param string|array $config
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
     * Check if a password matches a given hash string.
     *
     * @param string $password Password string
     * @param string $hash Hash string
     * @return boolean Returns true if the password matches, false otherwise
     */
    public static function verify($password, $hash)
    {
        return ($hash === static::hash($password, $hash));
    }

}