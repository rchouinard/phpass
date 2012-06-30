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
 *<code>
 * <?php
 * use PHPassLib\Hash\PBKDF2;
 *
 * $hash = PBKDF2::hash($password);
 * if (PBKDF2::verify($password, $hash)) {
 *     // Password matches, user is authenticated
 * }
 * </code>
 *
 * @link http://tools.ietf.org/html/rfc2898#section-5.2 PBKDF2 specification
 *     in RFC2898
 * @link http://en.wikipedia.org/wiki/PBKDF2 PBKDF2 at Wikipedia
 * @link http://packages.python.org/passlib/lib/passlib.hash.pbkdf2_digest.html
 *     PBKDF2-<digest> documentation from Python's PassLib
 */
class PBKDF2 implements Hash
{

    /**
     * Generate a config string suitable for use with pbkdf2 hashes.
     *
     * Available options:
     *  - digest: The underlying digest to use. Can be one of sha1, sha256, or
     *      sha512. Defaults to sha512.
     *  - rounds: Number of rounds to use when generating the hash. This number
     *      must be between 1 and 4294967296 inclusive. Default is 12000.
     *  - salt: If provided, should be a raw string between 1 and 1024 bytes.
     *      It is recommended to leave this blank and let the class generate
     *      a salt for you.
     *  - saltSize: The number of bytes to use when generating a salt string.
     *      Must be a number between 0 and 1024 inclusive. Defaults to 16.
     *
     * @param array $config Array of configuration options.
     * @return string Configuration string in the format
     *     "$pbkdf2-<digest>$<rounds>$<salt>$".
     * @throws InvalidArgumentException Throws an InvalidArgumentException if
     *     any passed-in configuration options are invalid.
     */
    public static function genConfig(Array $config = array ())
    {
        $defaults = array (
            'digest' => 'sha512',
            'rounds' => 12000,
            'salt' => null,
            'saltsize' => 16,
        );
        $config = array_merge($defaults, array_change_key_case($config, CASE_LOWER));

        // Generate a salt value if we need one
        if (!$config['salt'] && (int) $config['saltsize'] > 0) {
            $config['salt'] = static::genSalt(Utilities::genRandomBytes((int) $config['saltsize']));
        }

        if (static::validateOptions($config)) {
            // pbkdf2-sha1 doesn't include the digest in the hash identifier
            return str_replace('-sha1', '', sprintf('$pbkdf2-%s$%d$%s$', $config['digest'], (int) $config['rounds'], $config['salt']));
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
        // pbkdf2-sha1 doesn't include the digest in the identifier. It's added
        // for internal testing only.
        $config = str_replace('$pbkdf2$', '$pbkdf2-sha1$', $config);

        $matches = array ();
        $hash = ($config == '*0') ? '*1' : '*0';
        if (preg_match('/^\$pbkdf2-(sha1|sha256|sha512)\$(\d+)\$([\.\/0-9A-Za-z]*)\$?/', $config, $matches)) {
            $config = array (
                'digest' => $matches[1],
                'rounds' => $matches[2],
                'salt' => $matches[3],
            );

            // Hackish way to validate the $config array
            try {
                static::genConfig($config);
            } catch (InvalidArgumentException $e) {
                return '*0';
            }

            $keysize = 64;
            if ($config['digest'] == 'sha256') {
                $keysize = 32;
            } else if ($config['digest'] == 'sha1') {
                $keysize = 20;
            }

            $checksum = static::hashPbkdf2($password, Utilities::altBase64Decode($config['salt']), $config['rounds'], $keysize, $config['digest']);
            $hash = static::genConfig($config) . Utilities::altBase64Encode($checksum);
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
    protected static function validateOptions(Array $options)
    {
        $options = array_change_key_case($options, CASE_LOWER);
        foreach ($options as $option => $value) switch ($option) {

            case 'digest':
                if (!in_array($value, array ('sha1', 'sha256', 'sha512'))) {
                    throw new InvalidArgumentException('Digest must be one of sha1, sha256, or sha512');
                }
                break;

            case 'rounds':
                if (substr($value, 0, 1) == 0 || $value < 1 || (int) $value > 4294967296) {
                    throw new InvalidArgumentException('Rounds must be a number between 1 and 4294967296');
                }
                break;

            case 'salt':
                if (!preg_match('/^[\.\/0-9A-Za-z]{0,1024}$/', $value)) {
                    throw new InvalidArgumentException('Salt must be a string containing only the characters ./0-9A-Za-z');
                }
                break;

            default:
                break;

        }

        return true;
    }

}