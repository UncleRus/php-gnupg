<?php
/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @version 0.0.2
 * @author Ruslan V. Uss
 *
 * homepage: https://github.com/UncleRus/php-gnupg
 */

class GpgError extends Exception {}

class GpgProcError extends GpgError
{
	public function __construct ($binary)
	{
		parent::__construct ('Cannot execute GnuPG binary ('. $binary  . ')');
	}
}

class GpgUnknownStatus extends GpgError
{
	public function __construct ($status)
	{
		parent::__construct ('Uknown GnuPG status: ' . $status);
	}
}

class GpgSmartcardError extends GpgError
{
	static private $reasons = array (
		'Unspecified error',
		'Canceled',
		'Bad PIN'
	);

	public function __construct ($code)
	{
		parent::__construct (isset (self::$reasons [$code]) ? self::$reasons [$code] : 'Unknown error');
	}
}

class GpgNoDataError extends GpgError
{
	public function __construct ()
	{
		parent::__construct ('No valid data found');
	}
}

class GpgPassphraseError extends GpgError {}

class GpgKeyError extends GpgError {}

class GpgAlgorithmError extends GpgError {}

class GpgDecryptError extends GpgError {}


abstract class GpgUtils
{
	static public function multiSplit ($str)
	{
		return preg_split ('/\s+/', $str);
	}

	static public function getTimestamp ($value)
	{
		return strpos ($value, 'T') === false
			? (int) $value
			: DateTime::createFromFormat ('Ymd\THis', $value)->getTimestamp ();
	}
}

/**
 * Base class for result of GPG operation
 */
abstract class GpgResult
{
	/**
	 * GnuPG output
	 * @var string
	 */
	public $data;

	public $err;

	public function __construct ($data)
	{
		$this->data = $data ['data'];
		$this->err = $data ['err'];
		foreach ($data ['status'] as $row)
		{
			echo "HANDLE: " . $row [0] . ' : ' . $row [1] . "\n";
			$this->handle ($row [0], $row [1]);
		}
	}

	abstract public function handle ($key, $value);
}

/**
 * Single GPG import result
 */
class GpgImportKey
{
	/**
	 * Imported key fingerprint
	 * @var string
	 */
	public $fingerprint;

	/**
	 * True, if key has been imported
	 * @var bool
	 */
	public $imported;

	/**
	 * Raw integer result
	 * @var integer
	 */
	public $result;

	/**
	 * Import problem code
	 * @var integer
	 */
	public $problem;

	/**
	 * Description of result
	 * @var array of strings
	 */
	public $reasons = array ();

	static private $okReasons = array (
		1 => 'Entirely new key',
		2 => 'New user IDs',
		4 => 'New signatures',
		8 => 'New subkeys',
		16 => 'Contains private key'
	);

	static private $problemReasons = array (
        1 => 'Invalid certificate',
        2 => 'Issuer certificate missing',
        3 => 'Certificate chain too long',
        4 => 'Error storing certificate',
		5 => 'Key expired',
		6 => 'Signature expired'
	);

	public function __construct ($fingerprint, $result, $problem)
	{
		$this->fingerprint = $fingerprint;
		$this->imported = $result > 0;
		$this->result = $result;
		if ($this->imported)
		{
			foreach (self::$okReasons as $code => $text)
				if ($result & $code)
					$this->reasons [] = $text;
		}
		elseif ($fingerprint)
			$this->reasons [] = 'Not actually changed';
		$this->problem = $problem;
		if ($problem)
			$this->reasons [] = self::$problemReasons [$problem];
	}
}

/**
 * Import keys result.
 */
class GpgImportResult extends GpgResult
{
	static private $_counts = array (
		'count', 'noUserId', 'imported', 'importedRsa', 'unchanged',
		'nUids', 'nSubk', 'nSigs', 'nRevoked', 'secRead', 'secImported',
		'secDups', 'notImported'
	);

	/**
	 * Array of import results.
	 * @var array
	 */
	public $results = array ();

	/**
	 * Summary counters. All of them also available as object properties.
	 * @var array
	 */
	public $counts = array ();

	public function handle ($key, $value)
	{
		switch ($key)
		{
			case 'IMPORTED':
				// this duplicates info we already see in import_ok & import_problem
				break;
			case 'NODATA':
				throw new GpgNoDataError ();
			case 'IMPORT_OK':
				list ($reason, $fingerprint) = GpgUtils::multiSplit ($value);
				$reason = (int) $reason;
				$this->results [] = new GpgImportKey ($fingerprint, $reason, 0);
				break;
			case 'IMPORT_PROBLEM':
				@list ($reason, $fingerprint) = GpgUtils::multiSplit ($value);
				$this->results [] = new GpgImportKey ($fingerprint, 0, $reason);
				break;
			case 'IMPORT_RES':
				$result = GpgUtils::multiSplit ($value);
				foreach (self::$_counts as $i => $count)
					$this->counts [$count] = (int) $result [$i];
				break;
			case 'KEYEXPIRED':
				$this->results [] = new GpgImportKey (null, 0, 5);
				break;
			case 'SIGEXPIRED':
				$this->results [] = new GpgImportKey (null, 0, 6);
				break;
			default:
				throw new GpgUnknownStatus ($key);
		}
	}

	public function __get ($attr)
	{
		if (!in_array ($attr, self::$_counts))
			throw new Exception ('Unknown property ' . $attr);
		return isset ($this->counts [$attr]) ? $this->counts [$attr] : 0;
	}
}


/**
 * genKey() result.
 */
class GpgGenKeyResult extends GpgResult
{
	/**
	 * Key type.
	 * @var string
	 */
	public $type;

	/**
	 * Key fingerprint.
	 * @var string
	 */
	public $fingerprint;

	public function __construct ($data)
	{
		parent::__construct ($data);
		if (!$this->fingerprint)
			throw new GpgError (trim ($this->err));
	}

	public function handle ($key, $value)
	{
		switch ($key)
		{
			case 'PROGRESS':
			case 'GOOD_PASSPHRASE':
			case 'NODATA':
				break;
			case 'KEY_NOT_CREATED':
				throw new GpgError ('Key not created: ' . trim ($this->err));
				break;
			case 'KEY_CREATED':
				list ($this->type, $this->fingerprint) = GpgUtils::multiSplit ($value);
				break;
			default:
				throw new GpgUnknownStatus ($key);
		}
	}
}

/**
 * listKeys() result
 * result contains in $keys property
 */
class GpgListKeysResult extends GpgResult
{
	static private $keywords = array (
		'pub' => 1, 'uid' => 1, 'sec' => 1, 'fpr' => 1, 'sub' => 1
	);
	static private $fields = array (
		'trust', 'length', 'algo', 'keyid', 'date', 'expires', 'dummy', 'ownertrust', 'uid'
	);
	static private $intFields = array (
		'length' => 1, 'algo' => 1, 'date' => 1, 'expires' => 1
	);

	/**
	 * Keys data
	 * @var array
	 */
	public $keys = array ();

	private $current = array ();

	public function __construct ($data)
	{
		parent::__construct ($data);
		$this->data = explode ("\n", $this->data);
		foreach ($this->data as $line)
		{
			$line = trim ($line);
			if (!$line) continue;
			$fields = explode (':', $line);
			if (!isset (self::$keywords [$fields [0]]))
				continue;
			$this->handle ($fields [0], array_slice ($fields, 1));
		}
		if (!empty ($this->current))
			$this->keys [$this->current ['fingerprint']] = $this->current;
	}

	public function handle ($key, $value)
	{
		switch ($key)
		{
			case 'pub':
			case 'sec':
				if (!empty ($this->current))
					$this->keys [$this->current ['fingerprint']] = $this->current;
				$this->current = array ();
				foreach (self::$fields as $i => $field)
					$this->current [$field] = isset (self::$intFields [$field]) ? (int) $value [$i] : $value [$i];
				$this->current ['uid'] = $this->current ['uid'] != '' ? array ($this->current ['uid']) : array ();
				$this->current ['subkeys'] = array ();
				unset ($this->current ['dummy']);
				break;
			case 'uid':
				$this->current ['uid'][] = $value [8];
				break;
			case 'fpr':
				$this->current ['fingerprint'] = $value [8];
				break;
			case 'sub':
				$this->current ['subkeys'][] = array ($value [3], $value [10]);
				break;
		}
	}
}


/**
 * exportKeys() result
 */
class GpgExportResult extends GpgResult
{
	public function __construct ($data)
	{
		$this->data = $data ['data'];
		$this->err = trim ($data ['err']);
		if ($this->err)
			throw new GpgError ($this->err);
	}

	public function handle ($key, $value) {}
}

/**
 * deleteKeys() result.
 */
class GpgDeleteResult extends GpgResult
{
	private static $reasons = array (
		2 => 'Must delete secret key first',
		3 => 'Ambiguous specification'
	);

	public function handle ($key, $value)
	{
		if ($key == 'DELETE_PROBLEM')
		{
			if ($value == 1) return; // No key found
			throw new GpgError (isset (self::$reasons [$value]) ? self::$reasons [$value] : 'Unknown error: ' . $value);
		}
		else throw new GpgUnknownStatus ($key);
	}
}

/**
 * sign() result.
 * Actual sign contains in property $data.
 */
class GpgSignResult extends GpgResult
{
	/**
	 * Sign
	 * @var string
	 */
	public $data;

	/**
	 * Sign type
	 * @var string
	 */
	public $type;

	/**
	 * Sign algorithm
	 * @var int
	 */
	public $algorithm;

	/**
	 * Hash algorithm
	 * @var int
	 */
	public $hashAlgorithm;

	/**
	 * Key fingerprint
	 * @var string
	 */
	public $fingerprint;

	/**
	 * UTC timestamp of the sign
	 * @var int
	 */
	public $timestamp;

	public function handle ($key, $value)
	{
		switch ($key)
		{
			case 'USERID_HINT':
			case 'NEED_PASSPHRASE':
            case 'GOOD_PASSPHRASE':
			case 'BEGIN_SIGNING':
			case 'CARDCTRL':
			case 'KEYEXPIRED':
			case 'SIGEXPIRED':
			case 'KEYREVOKED':
			case 'SC_OP_SUCCESS':
				break;
			case 'INV_SGNR':
				list ($reason, $who) = GpgUtils::multiSplit ($value);
				throw new GpgError ('Invalid sender: ' . self::$invalidRecipient [$reason] . ' (' . $who . ')');
			case 'NO_SGNR':
				throw new GpgError ('No senders are usable');
			case 'SC_OP_FAILURE':
				throw new GpgSmartcardError ($value);
			case 'MISSING_PASSPHRASE':
				throw new GpgPassphraseError ('Missing passphrase');
			case 'BAD_PASSPHRASE':
				throw new GpgPassphraseError ('Bad passphrase');
			case 'SIG_CREATED':
				list (
					$this->type, $this->algorithm, $this->hashAlgorithm,
					$cls, $this->timestamp, $this->fingerprint
				) = GpgUtils::multiSplit ($value);
				$this->algorithm = (int) $this->algorithm;
				$this->hashAlgorithm = (int) $this->hashAlgorithm;
				$this->timestamp = GpgUtils::getTimestamp ($this->timestamp);
				break;
			default:
				throw new GpgUnknownStatus ($key);
		}
	}
}

/**
 * verify() result
 */
class GpgVerifyResult extends GpgResult
{
	private static $pass = array (
		'RSA_OR_IDEA', 'IMPORT_RES', 'PLAINTEXT',
		'PLAINTEXT_LENGTH', 'POLICY_URL', 'DECRYPTION_INFO',
		'DECRYPTION_OKAY', 'FILE_START', 'FILE_ERROR',
		'FILE_DONE', 'PKA_TRUST_GOOD', 'PKA_TRUST_BAD', 'BADMDC',
		'GOODMDC', 'TRUST_UNDEFINED', 'TRUST_NEVER',
		'TRUST_MARGINAL', 'TRUST_FULLY', 'TRUST_ULTIMATE'
	);

	// Signature expired
	const SIG_EXPIRED = 1;
	// Signature was made by an expired key
	const KEY_EXPIRED = 2;
	// Signature was made by a revoked key
	const KEY_REVOKED = 3;

	private static $states = array (
		'EXPSIG' => self::SIG_EXPIRED,
		'EXPKEYSIG' => self::KEY_EXPIRED,
		'REVKEYSIG' => self::KEY_REVOKED,
	);

	public $valid = false;
	public $fingerprint;
	public $timestamp;
	public $expireTimestamp;
	public $id;
	public $keyId;
	public $username;
	public $state = 0;

	protected function setProps ($value)
	{
		list ($this->keyId, $this->username) = explode (' ', $value, 2);
	}

	public function handle ($key, $value)
	{
		if (in_array ($key, self::$pass))
			return;
		switch ($key)
		{
			case 'NODATA':
				throw new GpgNoDataError ();
			case 'INV_RECP':
			case 'INV_SGNR':
				list ($reason, $who) = GpgUtils::multiSplit ($value);
				throw new GpgError (
					($key == 'INV_RECP' ? 'Invalid recipient: ' : 'Invalid sender: ')
						. self::$invalidRecipient [$reason] . ' (' . $who . ')'
				);
			case 'NO_SGNR':
				throw new GpgError ('No senders are usable');
			case 'NO_RECP':
				throw new GpgError ('No recipients are usable');
			case 'KEYEXPIRED':
			case 'SIGEXPIRED':
			case 'KEYREVOKED':
	            // these are useless in verify, since they are spit out for any
	            // pub/subkeys on the key, not just the one doing the signing.
	            // if we want to check for signatures with expired key,
	            // the relevant flag is EXPKEYSIG.
				break;
			case 'EXPSIG':
			case 'EXPKEYSIG':
			case 'REVKEYSIG':
				$this->valid = false;
				$this->state = self::$states [$key];
				$this->setProps ($value);
				break;
			case 'BADSIG':
				$this->valid = false;
				$this->setProps ($value);
				break;
			case 'ERRSIG':
				$this->valid = false;
				$raw = GpgUtils::multiSplit ($value);
				if ($raw [5] == 4)
					throw new GpgAlgorithmError ('Cannot verify signature: unsupported algorithm');
				elseif ($raw [5] == 9)
					throw new GpgKeyError ('Cannot verify signature: missing public key ' . $raw [0]);
				throw new GpgError ($msg);
			case 'GOODSIG':
				$this->valid = true;
				$this->setProps ($value);
				break;
			case 'VALIDSIG':
				// This status indicates that the signature is good. This is the same
				// as GOODSIG but has the fingerprint as the argument. Both status
				// lines are emitted for a good signature.
				list ($this->fingerprint, $_dummy,
					$this->timestamp, $this->expireTimestamp) = array_slice (GpgUtils::multiSplit ($value), 0, 4);
				$this->timestamp = GpgUtils::getTimestamp ($this->timestamp);
				break;
			case 'SIG_ID':
				list ($this->id, $_dummy, $this->timestamp) = GpgUtils::multiSplit ($value);
				$this->timestamp = GpgUtils::getTimestamp ($this->timestamp);
				break;
			case 'DECRYPTION_FAILED':
				throw new GpgDecryptError ('The symmetric decryption failed - one reason could be a wrong passphrase for a symmetrical encrypted message.');
			case 'NO_PUBKEY':
				throw new GpgKeyError ('Cannot verify signature: missing public key ' . $value);
			default:
				throw new GpgUnknownStatus ($key);
		}
	}
}


class GpgEncryptResult extends GpgVerifyResult
{
	private static $invalidRecipient = array (
		0 => 'No specific reason given',
		1 => 'Not Found',
		2 => 'Ambigious specification',
		3 => 'Wrong key usage',
		4 => 'Key revoked',
		5 => 'Key expired',
		6 => 'No CRL known',
		7 => 'CRL too old',
		8 => 'Policy mismatch',
		9 => 'Not a secret key',
		10 => 'Key not trusted',
		11 => 'Missing certificate',
		12 => 'Missing issuer certificate'
	);

	public $signatureExpired = false;

	public $keyExpired = false;

	public function handle ($key, $value)
	{
		switch ($key)
		{
			case 'ENC_TO':
			case 'USERID_HINT':
			case 'GOODMDC':
			case 'END_DECRYPTION':
			case 'BEGIN_SIGNING':
			case 'ERROR':
			case 'CARDCTRL':
			case 'BADMDC':
			case 'SC_OP_SUCCESS':
				// in the case of ERROR, this is because a more specific error
				// message will have come first
				break;
			case 'NODATA':
				throw new GpgNoDataError ();
			case 'NO_SECKEY':
				throw new GpgKeyError ('The secret key is not available (' . $value . ')');
			case 'SC_OP_FAILURE':
				throw new GpgSmartcardError ($value);
			case 'BAD_PASSPHRASE':
				throw new GpgPassphraseError ('Bad passphrase');
			case 'MISSING_PASSPHRASE':
				throw new GpgPassphraseError ('Missing passphrase');
			case 'KEY_NOT_CREATED':
				throw new GpgError (trim ($this->err));
			case 'NEED_PASSPHRASE':
			case 'GOOD_PASSPHRASE':
			case 'NEED_PASSPHRASE_SYM':
			case 'BEGIN_DECRYPTION':
			case 'BEGIN_ENCRYPTION':
			case 'DECRYPTION_OKAY':
			case 'END_ENCRYPTION':
			case 'SIG_CREATED':
				// Nothing to do
				break;
			case 'KEYEXPIRED':
				$this->keyExpired = true;
				break;
			case 'SIGEXPIRED':
				$this->signatureExpired = true;
				break;
			default:
				parent::handle ($key, $value);
		}
	}
}

/**
 * Encapsulate access to the gpg executable.
 */
class GnuPG
{
	/**
	 * Full pathname for GPG binary.
	 * @var string
	 */
	public $binary;

	/**
	 * Full pathname to where we can find the public and private keyrings.
	 * @var string
	 */
	public $homedir;

	/**
	 * Initialize a GPG process wrapper
	 * @param string $binary Full pathname for GPG binary.
	 * @param string $homedir Full pathname to where we can find the public and
        	private keyrings. Default is whatever gpg defaults to.
	 */
	public function __construct ($homedir = null, $binary = 'gpg')
	{
		$this->binary = $binary;
		$this->homedir = $homedir;
	}

	protected function execute ($args, $stdin = null, $passphrase = false)
	{
		$cmd = array ('--status-fd', '3', '--no-tty', '--lock-multiple', '--no-permission-warning');
		if ($this->homedir)
			$cmd = array_merge ($cmd, array ('--homedir', $this->homedir));
		if ($passphrase !== false)
			$cmd = array_merge ($cmd, array ('--batch', '--passphrase', $passphrase));
		$cmd = array_merge ($cmd, $args);
		foreach ($cmd as &$arg)
			$arg = escapeshellarg ($arg);
		$cmd = implode (' ', $cmd);

		//echo ">>> " . escapeshellcmd ($this->binary) . ' ' . $cmd . "\n";

		$process = proc_open (
			escapeshellcmd ($this->binary) . ' ' . $cmd,
			array (
				array ('pipe', 'r'),
				array ('pipe', 'w'),
				array ('pipe', 'w'),
				array ('pipe', 'w')
			),
			$pipes
		);

		if (!is_resource ($process))
			throw new GpgProcError ($this->binary);

		if (!is_null ($stdin))
		{
			fwrite ($pipes [0], $stdin);
			fclose ($pipes [0]);
		}

		$result = array (
			'data' => stream_get_contents ($pipes [1]),
			'err' => stream_get_contents ($pipes [2]),
			'status' => array ()
		);

		while (!feof ($pipes [3]))
		{
			$line = stream_get_line ($pipes [3], 1024, "\n");
			//echo "<<< " . $line . "\n";
			if (substr ($line, 0, 8) != '[GNUPG:]') continue;
			$l = explode (' ', substr ($line, 9), 2);
			$result ['status'][] = array ($l [0], count ($l) > 1 ? $l [1] : '');
		}
		fclose ($pipes [1]);
		fclose ($pipes [2]);
		fclose ($pipes [3]);
		proc_close ($process);
		return $result;
	}

	/**
	 * Import/merge keys. This adds the given keys to the keyring.
	 * @param string $keyData Keys data
	 * @return GpgImportResult
	 */
	public function importKeys ($keyData)
	{
		return new GpgImportResult (
			$this->execute (array ('--import'), $keyData)
		);
	}

	/**
	 * Import the keys with the given key IDs from a HKP keyserver.
	 * @param string $keyserver Keyserver name
	 * @param mixed $keys Single key ID string or array of multiple IDs
	 * @return GpgImportResult
	 */
	public function recvKeys ($keyserver, $keys)
	{
		if (!is_array ($keys))
			$keys = array ($keys);
		return new GpgImportResult (
			$this->execute (array_merge (array ('--keyserver', $keyserver, '--recv-keys'), $keys), '')
		);
	}

	/**
	 * Export keys
	 * @param mixed $keys Single key ID string or array of multiple IDs
	 * @param string $secret Export secret keys if true
	 * @param string $binary Armored format if true
	 * @return GpgExportResult
	 */
	public function exportKeys ($keys, $secret = false, $binary = false)
	{
		if (!is_array ($keys))
			$keys = array ($keys);
		$args = array_merge (($binary ? array ('--export') : array ('--armor', '--export')), $keys);
		return new GpgExportResult ($this->execute ($args));
	}

	/**
	 * List keys from the public or secret keyrings.
	 * @param bool $secret List secret keys when true
	 * @return GpgListKeysResult
	 */
	public function listKeys ($secret = false)
	{
		return new GpgListKeysResult (
			$this->execute (array (
				'--list-' . ($secret ? 'secret-keys' : 'keys'),
				'--fixed-list-mode',
				'--fingerprint',
				'--with-colons'
			)
		));
	}

	/**
	 * Check is given key exists
	 * @param string $key Key ID
	 * @param bool $secret Check secret key if true
	 * @return bool True if key exists
	 */
	public function keyExists ($key, $secret = false)
	{
		if (strlen ($key) < 8)
			return false;
		$key = strtoupper ($key);
		$res = $this->listKeys ($secret, $key);
		foreach ($res->keys as $fingerprint => $data)
			if (substr ($fingerprint, -strlen ($key)) == $key)
				return true;
		return false;
	}

	/**
	 * Remove keys from the public or secret keyrings.
	 * @param mixed $fingerprints Single key fingerprint string or array of multiple fingerprints
	 * @param bool $secret Delete secret keys when true
	 * @return GpgDeleteResult
	 */
	public function deleteKeys ($fingerprints, $secret = false)
	{
		if (!is_array ($fingerprints))
			$fingerprints = array ($fingerprints);
		return new GpgDeleteResult (
			$this->execute (
				array_merge (
					array ('--batch', '--delete-' . ($secret ? 'secret-key' : 'key')),
					$fingerprints
				)
			)
		);
	}

	/**
	 * Generate --gen-key input per gpg doc/DETAILS
	 * @param array $args Associative array of key parameters
	 * @return string
	 */
	public function genKeyInput ($args = array ())
	{
		$login = getenv ('LOGNAME');
		if (!$login)
			$login = getenv ('USERNAME');
		if (!$login)
			$login = 'user';
		$hostname = gethostname ();
		if (!$hostname)
			$hostname = 'localhost';
		$type = isset ($args ['Key-Type']) ? $args ['Key-Type'] : 'RSA';
		$params = $args + array (
			'Key-Length' => 1024,
			'Name-Real' => 'Autogenerated Key',
			'Name-Comment' => 'Generated by php-gnupg',
			'Name-Email' => $login . '@' . $hostname
		);
		$out = 'Key-Type: ' . $type . PHP_EOL;
		foreach ($params as $param => $value)
			$out .= $param . ': ' . $value . PHP_EOL;
		return $out . '%commit' . PHP_EOL;
	}

	/**
	 * Generate a new key pair; you might use genKeyInput() to create the control input.
	 * @param string $input GnuPG key generation control input
	 * @return GpgGenKeyResult
	 */
	public function genKey ($input)
	{
		return new GpgGenKeyResult (
			$this->execute (array ('--gen-key', '--batch'), $input)
		);
	}

	/**
	 * Make a signature.
	 * @param string $message Message for sign.
	 * @param string $keyId key for signing, default will be used if null
	 * @param string $passphrase key password
	 * @param bool $clearsign Make a clear text signature.
	 * @param bool $detach Make a detached signature.
	 * @param bool $binary If false, create ASCII armored output.
	 * @return GpgSignResult
	 */
	public function sign ($message, $keyId = null, $passphrase = null,
			$clearsign = true, $detach = false, $binary = false)
	{
		$args = array ($binary ? '-s' : '-sa');
		if ($detach)
			$args [] = '--detach-sign';
		elseif ($clearsign)
			$args [] = '--clearsign';
		if ($keyId)
			$args = array_merge ($args, array ('--default-key', $keyId));
		return new GpgSignResult (
			$this->execute ($args, $message, $passphrase)
		);
	}

	/**
	 * Make a signature.
	 * Warning: Entire file will be loaded into memory.
	 * @param string $filename File for sign.
	 * @param string $keyId key for signing, default will be used if null
	 * @param string $passphrase key password
	 * @param bool $clearsign Make a clear text signature.
	 * @param bool $detach Make a detached signature.
	 * @param bool $binary If false, create ASCII armored output.
	 * @return GpgSignResult
	 */
	public function signFile ($filename, $keyId = null, $passphrase = null,
			$clearsign = true, $detach = false, $binary = false)
	{
		return $this->sign (
			file_get_contents ($filename),
			$keyId, $passphrase, $clearsign, $detach, $binary
		);
	}

	/**
	 * Verify given signature
	 * @param string $sign Signature to verify
	 * @param string $dataFilename Assume signature is detached when not null
	 * @return GpgVerifyResult
	 */
	public function verify ($sign, $dataFilename = null)
	{
		if (is_null ($dataFilename))
			$res = $this->execute (array ('--verify'), $sign);
		else
		{
			// Handling detached verification
			$signFilename = tempnam (sys_get_temp_dir (), 'php-gnupg');
			file_put_contents ($signFilename, $sign);
			$res = $this->execute (array ('--verify', $signFilename, $dataFilename));
		}
		if (isset ($signFilename))
			unlink ($signFilename);
		return new GpgVerifyResult ($res);
	}

	/**
	 * Encrypt/sign message
	 * @param string $data data to encrypt
	 * @param mixed $recipients Single key fingerprint string or array of multiple fingerprints
	 * @param string $signKey Key ID for sign. If null, do not sign
	 * @param string $passphrase Key passphrase
	 * @param string $alwaysTrust When true, skip key validation and assume that used keys are always fully trusted.
	 * @param string $outputFilename If not null, encrypted data will be written to file
	 * @param string $binary If false, create ASCII armored output.
	 * @param string $symmetric Encrypt with symmetric cipher only
	 * @return GpgEncryptResult
	 */
	public function encrypt ($data, $recipients, $signKey = null, $passphrase = null,
			$alwaysTrust = false, $outputFilename = null, $binary = false, $symmetric = false)
	{
		if (!is_array ($recipients))
			$recipients = array ($recipients);
		if ($symmetric)
			$args = array ('--symmetric');
		else
		{
			$args = array ('--encrypt');
			foreach ($recipients as $recipient)
			{
				$args [] = '--recipient';
				$args [] = $recipient;
			}
		}
		if (!$binary)
			$args [] = '--armor';
		if ($outputFilename)
		{
			// to avoid overwrite confirmation message
			if (file_exists ($outputFilename))
				unlink ($outputFilename);
			$args = array_merge ($args, array ('--output', $outputFilename));
		}
		if ($signKey)
			$args = array_merge ($args, array ('--sign', '--default-key', $signKey));
		if ($alwaysTrust)
			$args [] = '--always-trust';
		return new GpgEncryptResult (
			$this->execute ($args, $data, $passphrase)
		);
	}

	/**
	 * Encrypt/sign file
	 * Warning: Entire file will be loaded into memory.
	 * @param mixed $recipients Single key fingerprint string or array of multiple fingerprints
	 * @param string $signKey Key ID for sign. If null, do not sign
	 * @param string $passphrase Key passphrase
	 * @param string $alwaysTrust When true, skip key validation and assume that used keys are always fully trusted.
	 * @param string $outputFilename If not null, encrypted data will be written to file
	 * @param string $binary If false, create ASCII armored output.
	 * @param string $symmetric Encrypt with symmetric cipher only
	 * @return GpgEncryptResult
	 */
	public function encryptFile ($filename, $recipients, $signKey = null, $passphrase = null,
			$alwaysTrust = false, $outputFilename = null, $binary = false, $symmetric = false)
	{
		return $this->encrypt (
			file_get_contents ($filename),
			$recipients, $signKey, $passphrase,
			$alwaysTrust, $outputFilename, $binary, $symmetric
		);
	}

	/**
	 * Decrypt/verify message
	 * @param string $data Data to decrypt
	 * @param string $passphrase Passphrase
	 * @param string $sender Sender key ID. If null, do not verify
	 * @param string $alwaysTrust When true, skip key validation and assume that used keys are always fully trusted.
	 * @param string $outputFilename If not null, decrypted data will be written to file
	 * @return GpgEncryptResult
	 */
	public function decrypt ($data, $passphrase, $sender = null, $alwaysTrust = false, $outputFilename = null)
	{
		$args = array ('--decrypt');
		if ($outputFilename)
		{
			// to avoid overwrite confirmation message
			if (file_exists ($outputFilename))
				unlink ($outputFilename);
			$args = array_merge ($args, array ('--output', $outputFilename));
		}
		if (!is_null ($sender))
			$args = array_merge ($args, array ('-u', $sender));
		if ($alwaysTrust)
			$args [] = '--always-trust';
		return new GpgEncryptResult ($this->execute ($args, $data, $passphrase));
	}

	/**
	 * Decrypt/verify file
	 * Warning: Entire file will be loaded into memory.
	 * @param string $filename Filename
	 * @param string $passphrase Passphrase
	 * @param string $sender Sender key ID. If null, do not verify
	 * @param string $alwaysTrust When true, skip key validation and assume that used keys are always fully trusted.
	 * @param string $outputFilename If not null, decrypted data will be written to file
	 * @return GpgEncryptResult
	 */
	public function decryptFile ($filename, $passphrase, $sender = null, $alwaysTrust = false, $outputFilename = null)
	{
		return $this->decrypt (
			file_get_contents ($filename),
			$passphrase, $sender, $alwaysTrust, $outputFilename
		);
	}
}
