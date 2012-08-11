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
use PHPassLib\Exception\RuntimeException;

/**
 * PBKDF2-SHA1/256/512 Module
 *
 * This module provides three hash schemes compatible with Python PassLib's
 * pbkdf2_<digest> schemes. PBKDF2-SHA512 is recommended for new applications.
 *
 * See http://packages.python.org/passlib/lib/passlib.hash.pbkdf2_digest.html
 * for more details about this hash scheme.
 *
 * The PBKDF2 specification uses the HMAC variant of the SHA-1 hash function,
 * which is not vulnerable to any of the known SHA-1 weaknesses. Any of the
 * three digests are perfectly safe to use.
 *
 * Supported parameters:
 *
 * <ul>
 *   <li><b>digest:</b> Must be one of sha1, sha256, or sha512. Defaults to
 *   sha512.</li>
 *
 *   <li><b>rounds:</b> Optional number of rounds to use. Must be an integer
 *   between 1 and 4294967296 inclusive. Defaults to 12000.</li>
 *
 *   <li><b>saltSize:</b> Optional number of bytes to use when generating new
 *   salts. Must be an integer between 0 and 1024 inclusive. Defaults to 16.</li>
 *
 *   <li><b>salt:</b> Optional salt string. If provided, it must be a string
 *   between 0 and 1024 characters in length. It is highly recommended that
 *   this parameter be left blank, in which case the library will generate a
 *   suitable salt for you.</li>
 * </ul>
 *
 * This module requires the <i>HASH Message Digest Framework</i> extension to
 * be loaded in order to work.
 *
 * @package PHPassLib\Hashes
 * @author Ryan Chouinard <rchouinard@gmail.com>
 * @copyright Copyright (c) 2012, Ryan Chouinard
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 */
class PBKDF2 implements Hash
{

    const DIGEST_SHA1 = 'sha1';
    const DIGEST_SHA256 = 'sha256';
    const DIGEST_SHA512 = 'sha512';

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
            'digest' => self::DIGEST_SHA512,
            'rounds' => 12000,
            'salt' => null,
            'saltsize' => 16,
        );
        $config = array_merge($defaults, array_change_key_case($config, CASE_LOWER));

        $string = '*1';
        if (self::validateOptions($config)) {
            // Generate a salt value if we need one
            if ($config['salt'] === null && (int) $config['saltsize'] > 0) {
                $config['salt'] = self::genSalt(Utilities::genRandomBytes((int) $config['saltsize']));
            }

            // pbkdf2-sha1 doesn't include the digest in the hash identifier
            // We also have to treat the rounds parameter as a float, otherwise
            // values above 2147483647 will wrap on 32-bit systems.
            $string = str_replace('-sha1', '', sprintf('$pbkdf2-%s$%0.0f$%s', $config['digest'], $config['rounds'], $config['salt']));
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
        if (preg_match('/^\$pbkdf2(?:-(sha256|sha512))?\$(\d+)\$([\.\/0-9A-Za-z]{0,1366})\$?/', $config, $matches)) {
            $options = array (
                'digest' => $matches[1] ?: 'sha1',
                'rounds' => $matches[2],
                'salt' => $matches[3],
                'saltSize' => $matches[3] ? strlen(Utilities::altBase64Decode($matches[3])) : 0,
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
     * @throws RuntimeException Throws a RuntimeException if the required
     *     HASH Message Digest Framework is not not loaded.
     */
    public static function genHash($password, $config)
    {
        $hash = ($config == '*0') ? '*1' : '*0';

        $config = self::parseConfig($config);
        if (is_array($config)) {
            $keysize = 64;
            if ($config['digest'] == self::DIGEST_SHA256) {
                $keysize = 32;
            } elseif ($config['digest'] == self::DIGEST_SHA1) {
                $keysize = 20;
            }

            // hashPbkdf2() will throw a runtime exception if ext-hash
            // is not loaded.
            $checksum = self::hashPbkdf2($password, Utilities::altBase64Decode($config['salt']), $config['rounds'], $keysize, $config['digest']);
            $hash = self::genConfig($config) . '$' . Utilities::altBase64Encode($checksum);
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
     * @throws RuntimeException Throws a RuntimeException if the required
     *     HASH Message Digest Framework is not not loaded.
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

        return Utilities::altBase64Encode($input);
    }

    /**
     * Implementation of the PBKDF2 algorithm.
     *
     * @param string $password Password string.
     * @param string $salt Salt string.
     * @param integer $rounds Number of rounds to use.
     * @param integer $keyLength Desired length of key.
     * @param string $digest Digest to use.
     * @return string Returns the raw byte string of the derived key.
     * @throws RuntimeException Throws a RuntimeException if the required
     *     HASH Message Digest Framework is not not loaded.
     */
    protected static function hashPbkdf2($password, $salt, $rounds = 12000, $keyLength = 64, $digest = 'sha512')
    {
        if (!extension_loaded('hash')) {
            throw new RuntimeException('Required extension "hash" not loaded: PBKDF2 requires the HASH Message Digest Framework.');
        }

        $hashLength = strlen(hash($digest, null, true));
        $keyBlocks = ceil($keyLength / $hashLength);
        $derivedKey = '';

        for ($block = 1; $block <= $keyBlocks; ++$block) {
            $iteratedBlock = $currentBlock = hash_hmac($digest, $salt . pack('N', $block), $password, true);
            for ($iteration = 1; $iteration < $rounds; ++$iteration) {
                $iteratedBlock ^= $currentBlock = hash_hmac($digest, $currentBlock, $password, true);
            }

            $derivedKey .= $iteratedBlock;
        }

        return substr($derivedKey, 0, $keyLength);
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

            case 'digest':
                if (!in_array($value, array (self::DIGEST_SHA1, self::DIGEST_SHA256, self::DIGEST_SHA512))) {
                    throw new InvalidArgumentException('Invalid digest parameter');
                }
                break;

            case 'rounds':
                if (substr($value, 0, 1) == 0 || $value < 1 || $value > 4294967296) {
                    throw new InvalidArgumentException('Invalid rounds parameter');
                }
                break;

            case 'saltsize':
                if ($value > 1024) {
                    throw new InvalidArgumentException('Invalid salt size parameter');
                }
                break;

            case 'salt':
                if (!preg_match('/^[\.\/0-9A-Za-z]{0,1366}$/', $value)) {
                    throw new InvalidArgumentException('Invalid salt parameter');
                }
                break;

            default:
                break;

        }

        return true;
    }

}
