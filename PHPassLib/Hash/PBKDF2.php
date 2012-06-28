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
class PBKDF2 implements Hash
{

    /**
     * Generate a config string suitable for use with pbkdf2 hashes
     *
     * Available options:
     *  - digest: The underlying digest to use. Can be one of sha1, sha256, or
     *      sha512. Defaults to sha512.
     *  - rounds: Number of rounds to use when generating the hash. This number
     *      must be between 1 and 4294967296 inclusive. default is 12000.
     *  - salt: If provided, should be a raw string between 1 and 1024 bytes.
     *      It is recommended to leave this blank and let the class generate
     *      a salt for you.
     *  - saltSize: The number of bytes to use when generating a salt string.
     *      Must be a number between 0 and 1024 inclusive. Defaults to 16.
     *
     * @param array $config Array of configuration options
     * @return string Configuration string in the format
     *     $pbkdf2-<digest>$<rounds>$<salt>$
     * @throws InvalidArgumentException Throws an InvalidArgumentException if
     *     any passed-in configuration options are invalid
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

        if (!in_array($config['digest'], array ('sha1', 'sha256', 'sha512'))) {
            throw new InvalidArgumentException('Digest must be one of sha1, sha256, or sha512');
        }

        if (substr($config['rounds'], 0, 1) == 0 || (int) $config['rounds'] < 1 || (int) $config['rounds'] > 4294967296) {
            throw new InvalidArgumentException('Rounds must be a number between 1 and 4294967296');
        }

        // Validate or generate a new salt value
        if (!$config['salt']) {
            if ((int) $config['saltsize'] < 0 || (int) $config['saltsize'] > 1024) {
                throw new InvalidArgumentException('Salt size must be a number between 0 and 1024');
            }
            if ((int) $config['saltsize'] > 0) {
                $config['salt'] = static::genSalt(Utilities::genRandomBytes((int) $config['saltsize']));
            }
        }

        if ($config['salt'] && !preg_match('/^[\.\/0-9A-Za-z]+$/', $config['salt'])) {
            throw new InvalidArgumentException('Salt must be a string containing only the characters ./0-9A-Za-z');
        }

        // pbkdf2-sha1 doesn't include the digest in the identifier.
        return str_replace('-sha1', '', sprintf('$pbkdf2-%s$%d$%s$', $config['digest'], (int) $config['rounds'], $config['salt']));
    }

    /**
     * Generate a hash using a pre-defined config string
     *
     * @param string $password
     * @param string $config
     * @return string
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
     * Generate a hash using either a pre-defined config string or an array
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
     * Check if a password matches a given hash string
     *
     * @param string $password Password string
     * @param string $hash Hash string
     * @return boolean Returns true if the password matches, false otherwise
     */
    public static function verify($password, $hash)
    {
        return ($hash === static::hash($password, $hash));
    }

    /**
     * Generate a salt string
     *
     * @param string $input
     * @return string
     */
    protected static function genSalt($input = null)
    {
        return Utilities::altBase64Encode($input ?: Utilities::genRandomBytes(16));
    }

    /**
     * Implementation of the PBKDF2 algorithm
     *
     * @param string $password
     * @param string $salt
     * @param integer $iterationCount
     * @param integer $keyLength
     * @param string $algo
     * @return string Returns the raw byte string of the derived key
     */
    protected static function hashPbkdf2($password, $salt, $iterationCount = 12000, $keyLength = 20, $algo = 'sha1')
    {
        $hashLength = strlen(hash($algo, null, true));
        $keyBlocks = ceil($keyLength / $hashLength);
        $derivedKey = '';

        for ($block = 1; $block <= $keyBlocks; ++$block) {
            $iteratedBlock = $currentBlock = hash_hmac($algo, $salt . pack('N', $block), $password, true);
            for ($iteration = 1; $iteration < $iterationCount; ++$iteration) {
                $iteratedBlock ^= $currentBlock = hash_hmac($algo, $currentBlock, $password, true);
            }

            $derivedKey .= $iteratedBlock;
        }

        return substr($derivedKey, 0, $keyLength);
    }

}