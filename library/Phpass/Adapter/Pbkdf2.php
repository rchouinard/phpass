<?php
/**
 * Portable PHP password hashing framework.
 *
 * @package PHPass
 * @subpackage Adapters
 * @category Cryptography
 * @author Solar Designer <solar at openwall.com>
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link http://www.openwall.com/phpass/ Original phpass project page.
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */

/**
 * @namespace
 */
namespace Phpass\Adapter;
use Phpass\Exception\RuntimeException,
    Phpass\Exception\UnexpectedValueException;

/**
 * @see Phpass\Adapter\Base
 */
require_once 'Phpass/Adapter/Base.php';

/**
 * @see Phpass\Exception\RuntimeException
 */
require_once 'Phpass/Exception/RuntimeException.php';

/**
 * @see Phpass\Exception\UnexpectedValueException
 */
require_once 'Phpass/Exception/UnexpectedValueException.php';

/**
 * Portable PHP password hashing framework.
 *
 * @package PHPass
 * @subpackage Adapters
 * @category Cryptography
 * @author Solar Designer <solar at openwall.com>
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link http://www.openwall.com/phpass/ Original phpass project page.
 * @link https://github.com/rchouinard/phpass PHPass project at GitHub.
 */
class Pbkdf2 extends Base
{

    /**
     * @var string
     */
    protected $_algo;

    /**
     * @var integer
     */
    protected $_keyLength;

    /**
     * @var string
     */
    protected $_salt;

    /**
     * @param array $options
     * @return void
     */
    public function __construct(Array $options = array ())
    {
        $this->_algo = 'sha256';
        $this->_iterationCountLog2 = 12;
        $this->_keyLength = 32;

        $this->setOptions($options);
    }

    /**
     * (non-PHPdoc)
     * @see Phpass\Adapter\Base::crypt()
     */
    public function crypt($password, $salt = null)
    {
        $derivedKey = '';
        $iterationCount = (1 << $this->_iterationCountLog2);
        $hashLength = strlen(hash($this->_algo, null, true));
        $keyBlocks = ceil($this->_keyLength / $hashLength);

        if (!$salt) {
            $salt = $this->genSalt();
        }

        for ($block = 1; $block <= $keyBlocks; ++$block) {
            $iteratedBlock = hash_hmac($this->_algo, $salt . pack('N', $block), $password, true);

            for ($iteration = 1; $iteration < $iterationCount; ++$iteration) {
                $iteratedBlock ^= hash_hmac($this->_algo, $iteratedBlock, $password, true);
            }

            $derivedKey .= $iteratedBlock;
        }

        return substr($derivedKey, 0, $this->_keyLength);
    }

    /**
     * (non-PHPdoc)
     * @see Phpass\Adapter::genSalt()
     */
    public function genSalt($input)
    {
        if (!$this->_salt) {
            throw new RuntimeException('Salt value must be supplied when using PBKDF2 adapter');
        }

        return $this->_salt;
    }

    /**
     * (non-PHPdoc)
     * @see Phpass\Adapter::isSupported()
     */
    public function isSupported()
    {
        return extension_loaded('hash');
    }

    /**
     * (non-PHPdoc)
     * @see Phpass\Adapter::isValid()
     */
    public function isValid($hash)
    {
        return true;
    }

    /**
     * (non-PHPdoc)
     * @see Phpass\Adapter\Base::setOptions()
     */
    public function setOptions(Array $options)
    {
        $options = array_change_key_case($options, CASE_LOWER);

        foreach ($options as $key => $value) {
            switch ($key) {

                case 'algo':
                case 'algorithm':
                    if (!in_array($value, hash_algos())) {
                        throw new UnexpectedValueException("Hash algorithm '${$this->_hashAlgo}' is not supported on this system");
                    }
                    $this->_algo = $value;
                    break;

                case 'keyLength':
                    $this->_keyLength = (int) $value;
                    break;

                case 'salt':
                    $this->_salt = $value;
                    break;

                default:
                    break;

            }
        }

        parent::setOptions($options);
    }

}