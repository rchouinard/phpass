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

namespace PHPassLib;

/**
 * Hashing Module Interface
 *
 * This interface defines the methods the hashing modules are required to
 * expose publically. The defined API is designed to be simple and clear, using
 * static methods which are hopefully clearly named.
 *
 * <code>
 * &lt;?php
 * // This example uses BCrypt, but all the modules use the same API.
 * use PHPassLib\Hash\BCrypt;
 *
 * // genConfig() creates a configuration string which can then be passed
 * // to genHash to create a password hash. The output will be different
 * // each time due to the random salt value.
 * $config = BCrypt::genConfig();
 *
 * // $2a$12$/U9KJXjz9DJ71TvZ2pbLcO
 * echo $config;
 *
 * // genHash() takes both a password and a configuration string and uses
 * // them to generate a secure password hash.
 * $hash = BCrypt::genHash('password', $config);
 *
 * // $2a$12$/U9KJXjz9DJ71TvZ2pbLcOpMlEx0L95tMrD35/4suzvEr5lcB14NC
 * echo $hash;
 *
 * // hash() can be used as a shortcut for the above. This method will
 * // create a new configuration string, and is equivalent to running
 * // BCrypt::genHash('password', BCrypt::genConfig());
 * $hash = BCrypt::hash('password');
 *
 * // verify() is used to check if a password string matches a given hash.
 * if (BCrypt::verify('password', $hash)) {
 *     // Passwords match!
 * }
 * </code>
 *
 * The `genConfig()` and `hash()` methods can also be passed a configuration
 * array. The options set in the array modify the generated config string,
 * which in turn affects the calculated hash. Check the documentation for the
 * module you want to use for more details.
 *
 * @package PHPassLib\Hashes
 * @author Ryan Chouinard <rchouinard@gmail.com>
 * @copyright Copyright (c) 2012, Ryan Chouinard
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 */
interface Hash
{

    /**
     * Generate a config string suitable for use with module hashes.
     *
     * @param array $config Array of configuration options.
     * @return string Configuration string.
     * @throws InvalidArgumentException Throws an InvalidArgumentException if
     *     any passed-in configuration options are invalid.
     */
    public static function genConfig(array $config = array ());

    /**
     * Parse a config string and extract the options used to build it.
     *
     * @param string $config Configuration string.
     * @return array Options array or false on failure.
     */
    public static function parseConfig($config);

    /**
     * Generate a hash using a pre-defined config string.
     *
     * @param string $password Password string.
     * @param string $config Configuration string.
     * @return string Returns the hash string on success. On failure, one of
     *     *0 or *1 is returned.
     */
    public static function genHash($password, $config);

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
    public static function hash($password, $config = array ());

    /**
     * Verify a password against a hash string.
     *
     * @param string $password Password string.
     * @param string $hash Hash string.
     * @return boolean Returns true if the password matches, false otherwise.
     */
    public static function verify($password, $hash);

}