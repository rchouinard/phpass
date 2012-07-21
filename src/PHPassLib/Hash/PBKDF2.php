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
 * PBKDF2-<digest> Module
 *
 * PBKDF2 is the Password-Based Key Derivation function, v2. PBKDF2 uses a
 * configurable number of rounds in order to adjust its computational cost and
 * discourage brute-force attacks. It also uses a salt value in order to defeat
 * rainbow tables.
 *
 * This module is capable of generating PBKDF2 keys using the HMAC SHA-1,
 * SHA-256, or SHA-512. the SHA-1 variant is not vulnerable to any known SHA-1
 * weakness and may be used safely.
 *
 * It is recommended that pbkdf2-sha512 be used in new applications.
 *
 * <code>
 * &lt;?php
 * use PHPassLib\Hash\PBKDF2;
 *
 * $hash = PBKDF2::hash($password);
 * if (PBKDF2::verify($password, $hash)) {
 *     // Password matches, user is authenticated
 * }
 * </code>
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
            'digest' => self::DIGEST_SHA512,
            'rounds' => 12000,
            'salt' => null,
            'saltsize' => 16,
        );
        $config = array_merge($defaults, array_change_key_case($config, CASE_LOWER));

        $string = '*1';
        try {
            self::validateOptions($config);
            // Generate a salt value if we need one
            if ($config['salt'] === null && (int) $config['saltsize'] > 0) {
                $config['salt'] = self::genSalt(Utilities::genRandomBytes((int) $config['saltsize']));
            }

            // pbkdf2-sha1 doesn't include the digest in the hash identifier
            // We also have to treat the rounds parameter as a float, otherwise
            // values above 2147483647 will wrap on 32-bit systems.
            $string = str_replace('-sha1', '', sprintf('$pbkdf2-%s$%0.0f$%s', $config['digest'], $config['rounds'], $config['salt']));
        } catch (InvalidArgumentException $e) {
            trigger_error($e->getMessage(), E_USER_WARNING);
        } catch (RuntimeException $e) {
            trigger_error($e->getMessage(), E_USER_ERROR);
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
        if (preg_match('/^\$pbkdf2-?(sha256|sha512)?\$(\d+)\$([\.\/0-9A-Za-z]{0,1366})\$?/', $config, $matches)) {
            $options = array (
                'digest' => $matches[1] ?: 'sha1',
                'rounds' => $matches[2],
                'salt' => $matches[3],
                'saltSize' => $matches[3] ? strlen(Utilities::altBase64Decode($matches[3])) : 0,
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
        // pbkdf2-sha1 doesn't include the digest in the identifier. It's added
        // for internal testing only.
        $config = str_replace('$pbkdf2$', '$pbkdf2-sha1$', $config);

        // Set default hash value to an error string
        $hash = ($config == '*0') ? '*1' : '*0';

        // Extract options from config string
        $matches = array ();
        if (preg_match('/^\$pbkdf2-(sha1|sha256|sha512)\$(\d+)\$([\.\/0-9A-Za-z]*)\$?/', $config, $matches)) {
            $config = array (
                'digest' => $matches[1],
                'rounds' => $matches[2],
                'salt' => $matches[3],
            );
        }

        // If the configuration array isn't populated, return the error string
        if (!is_array($config)) {
            return $hash;
        }

        // Validate config string
        try {
            self::validateOptions($config);
        } catch (InvalidArgumentException $e) {
            return $hash;
        }

        // Determine the required key size
        $keysize = 64;
        if ($config['digest'] == self::DIGEST_SHA256) {
            $keysize = 32;
        } elseif ($config['digest'] == self::DIGEST_SHA1) {
            $keysize = 20;
        }

        // Calculate the checksum and encode the hash string
        $checksum = self::hashPbkdf2($password, Utilities::altBase64Decode($config['salt']), $config['rounds'], $keysize, $config['digest']);
        $hash = self::genConfig($config) . '$' . Utilities::altBase64Encode($checksum);

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

            case 'digest':
                if (!in_array($value, array (self::DIGEST_SHA1, self::DIGEST_SHA256, self::DIGEST_SHA512))) {
                    throw new InvalidArgumentException('Digest must be one of sha1, sha256, or sha512.');
                }
                break;

            case 'rounds':
                if (substr($value, 0, 1) == 0 || $value < 1 || $value > 4294967296) {
                    throw new InvalidArgumentException('Rounds must be a number in the range 1 - 4294967296.');
                }
                break;

            case 'saltsize':
                if ($value > 1024) {
                    throw new InvalidArgumentException('Salt size must be a number in the range 0 - 1024.');
                }
                break;

            case 'salt':
                if (!preg_match('/^[\.\/0-9A-Za-z]{0,1366}$/', $value)) {
                    throw new InvalidArgumentException('Salt must be a string matching the regex pattern /[./0-9A-Za-z]{0,1366}/.');
                }
                break;

            default:
                break;

        }

        return true;
    }

}