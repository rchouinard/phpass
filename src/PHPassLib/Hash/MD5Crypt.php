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
 * MD5 Crypt Module
 *
 * MD5 crypt is a cryptographic hash function which uses an algorithm based on
 * MD5 in combination with a salt value. The resulting function is more
 * computationally expensive, and therefore slower to calculate, than straigh
 * MD5. the slower speed helps to discourage brute-force attacks while the salt
 * value defeats rainbow tables.
 *
 * This method uses a fixed number of rounds and is no longer as
 * computationally expensive as it once was. It is not recommended to use
 * MD5 crypt for new projects. Consider using BCrypt or PBKDF2-SHA512 instead.
 *
 * <code>
 * &lt;?php
 * use PHPassLib\Hash\MD5Crypt;
 *
 * $hash = MD5Crypt::hash($password);
 * if (MD5Crypt::verify($password, $hash)) {
 *     // Password matches, user is authenticated
 * }
 * </code>
 *
 * @package PHPassLib\Hashes
 * @author Ryan Chouinard <rchouinard@gmail.com>
 * @copyright Copyright (c) 2012, Ryan Chouinard
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 */
class MD5Crypt implements Hash
{

    /**
     * Generate a config string suitable for use with module hashes.
     *
     * @param array $config Array of configuration options.
     * @return string Configuration string.
     * @throws InvalidArgumentException Throws an InvalidArgumentException if
     *     any passed-in configuration options are invalid.
     */
    public static function genConfig(array $config = array ())
    {
        $defaults = array (
            'salt' => self::genSalt(),
        );
        $config = array_merge($defaults, array_change_key_case($config, CASE_LOWER));

        $string = '*1';
        try {
            self::validateOptions($config);
            $string = sprintf('$1$%s', $config['salt']);
        } catch (InvalidArgumentException $e) {
            trigger_error($e->getMessage(), E_USER_WARNING);
        }

        return $string;
    }

    /**
     * Parse a config string and extract the options used to build it.
     *
     * @param string $config Configuration string.
     * @return array Options array or false on failure.
     */
    public static function parseConfig($config)
    {
        $options = false;
        $matches = array ();
        if (preg_match('/^\$1\$([\.\/0-9A-Za-z]{0,8})\$?/', $config, $matches)) {
            $options = array (
                'salt' => $matches[1],
            );
        }

        return $options;
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
        if (!preg_match('/^\$1\$[\.\/0-9A-Za-z]{0,8}\$[\.\/0-9A-Za-z]{22}$/', $hash)) {
            $hash = ($config == '*0') ? '*1' : '*0';
        }

        return $hash;
    }

    /**
     * Generate a hash using either a pre-defined config string or an array.
     *
     * @see Hash::genConfig()
     * @see Hash::genHash()
     * @param string $password Password string.
     * @param string|array $config Optional config string or array of options.
     * @return string Returns the hash string on success. On failure, one of
     *     *0 or *1 is returned.
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
     * Generate a valid salt string.
     *
     * @param string $input Optional random string of raw bytes.
     * @return string Encoded salt string.
     */
    protected static function genSalt($input = null)
    {
        if (!$input) {
            $input = Utilities::genRandomBytes(6);
        }

        return Utilities::encode64($input);
    }

    /**
     * Validate a set of module options.
     *
     * @param array $options Associative array of options.
     * @return boolean Returns true if all options are valid.
     * @throws InvalidArgumentException Throws an InvalidArgumentException
     *     if an invalid option value is encountered.
     */
    protected static function validateOptions(array $options)
    {
        $options = array_change_key_case($options, CASE_LOWER);
        foreach ($options as $option => $value) switch ($option) {

            case 'salt':
                if (!preg_match('/^[\.\/0-9A-Za-z]{0,8}$/', $value)) {
                    throw new InvalidArgumentException('Salt must be a string matching the regex pattern /[./0-9A-Za-z]{0,8}/.');
                }
                break;

            default:
                break;

        }

        return true;
    }

}