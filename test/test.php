#!/usr/bin/php5
<?php

function error_handler ($errno, $errstr)
{
	throw new Exception ($errstr, $errno);
}

set_error_handler ('error_handler');

class AssertionError extends Exception {}

abstract class TestCase
{
	public function setUp () {}
	public function tearDown () {}
	public function setUpClass () {}
	public function tearDownClass () {}

	public function assert ($expression, $message = null)
	{
		if (!$expression) throw new AssertionError ($message ? $message : 'Assertion failed');
	}

	public function assertFalse ($expression, $message = null)
	{
		$this->assert (!$expression, $message);
	}

	public function assertEquals ($value1, $value2, $message = null)
	{
		$this->assert ($value1 === $value2, $message ? $message : "$value1 !== $value2");
	}

	public function assertNotEquals ($value1, $value2, $message = null)
	{
		$this->assert ($value1 !== $value2, $message ? $message : "$value1 === $value2");
	}

	public function assertNull ($expression, $message = null)
	{
		$this->assert (is_null ($expression), $message);
	}

	public function assertNotNull ($expression, $message = null)
	{
		$this->assert (!is_null ($expression), $message);
	}

	public function assertEmpty ($expression, $message = null)
	{
		$this->assert (empty ($expression), $message ? $message : "$expression is not empty");
	}

	public function assertNotEmpty ($expression, $message = null)
	{
		$this->assert (!empty ($expression), $message ? $message : "Value is empty");
	}

	public function assertStartsWith ($value, $substring, $message = null)
	{
		$this->assertEquals (strpos ($value, $substring), 0, $message ? $message : "Value is not started with $substring");
	}

	public function runTest ($test)
	{
		$this->setUp ();
		try
		{
			$this->$test ();
			$this->tearDown ();
		}
		catch (Exception $e)
		{
			$this->tearDown ();
			throw $e;
		}
	}

	public function run ()
	{
		$passed = 0;
		$failed = 0;
		$this->setUpClass ();
		foreach (get_class_methods ($this) as $method)
		{
			if (substr ($method, 0, 4) != 'test') continue;
			echo "-------------------------------------------------------------\n";
			echo 'Running ' . $method . "...\n";
			try
			{
				$this->runTest ($method);
				$passed ++;
				echo "Passed.\n";
			}
			catch (Exception $e)
			{
				$failed ++;
				echo "Failed:\n";
				echo $e->getCode () . ': ' . $e->getMessage () . "\n";
			}
		}
		$this->tearDownClass ();
		echo "-------------------------------------------------------------\n";
		if ($failed > 0) echo "FAILURES!\n";
		echo 'Tests: ' . ($passed + $failed) . ', passed: ' . $passed . ', failed: ' . $failed . "\n";
	}
}

require_once '../gpg.php';

class GpgTest extends TestCase
{
	static public function remove_path ($path)
	{
		if (!is_dir ($path)) return;

		$objects = scandir ($path);
		foreach ($objects as $object)
		{
			if ($object == '.' || $object == '..') continue;
			$file = $path . '/' . $object;
			if (filetype ($file) == 'dir') self::remove_path ($file);
				else @unlink ($file);
		}
		@rmdir ($path);
	}

	const homedir = '/tmp/gpg-php-test-homedir';

	public $gpg;

	public function setUpClass ()
	{
		mkdir (self::homedir);
		$this->gpg = new GnuPG (self::homedir);
	}

	public function tearDownClass ()
	{
		self::remove_path (self::homedir);
	}

	/////////////////////////////////////////////////////////

	public function testImport ()
	{
		$res = $this->gpg->importKeys (file_get_contents ('key.txt'));
		$this->assertEquals ($res->results [0]['fingerprint'], '6C74DF21146E083BB6FB07545D189C58F0250410');
	}

	public function testListKeys ()
	{
		$res = $this->gpg->listKeys ();
		$this->assert (isset ($res->keys ['6C74DF21146E083BB6FB07545D189C58F0250410']), 'Key 6C74DF21146E083BB6FB07545D189C58F0250410 not found');
	}

	public function testRecvKeys ()
	{
		$res = $this->gpg->recvKeys ('keyserver.ubuntu.com', '3E5C1192');
		$this->assertEquals ($res->results [0]['fingerprint'], 'C47415DFF48C09645B78609416126D3A3E5C1192');
	}

	public function testKeyExists ()
	{
		$this->assert ($this->gpg->keyExists ('F0250410'));
		$this->assertFalse ($this->gpg->keyExists ('50410'));
	}

	public function testExportKeys ()
	{
		$res = $this->gpg->exportKeys ('F0250410');
		$this->assertStartsWith ($res->data, '-----BEGIN PGP PUBLIC KEY BLOCK-----');
	}

	public function testDeleteKeys ()
	{
		$this->gpg->deleteKeys ('C47415DFF48C09645B78609416126D3A3E5C1192');
		$this->assertEquals (count ($this->gpg->listKeys ()->keys), 1);
	}

	public function testGenKey ()
	{
		$input = $this->gpg->genKeyInput ();
		$res = $this->gpg->genKey ($input);
		$this->assertEquals ($res->type, 'P');
		$this->gpg->deleteKeys ($res->fingerprint, true);
		$this->gpg->deleteKeys ($res->fingerprint);
	}

	public function testSignVerify ()
	{
		$signer = $this->gpg->genKey ($this->gpg->genKeyInput (array ('Passphrase' => '123321')));
		$sign = $this->gpg->sign ('Message for sign', $signer->fingerprint, '123321');
		$this->assertStartsWith ($sign->data, '-----BEGIN PGP SIGNED MESSAGE-----');

		$res = $this->gpg->verify ($sign->data);
		$this->assert ($res->valid, 'Invalid sign');
	}

	public function testEncryptSignDecryptVerify ()
	{
		$sender = $this->gpg->genKey ($this->gpg->genKeyInput (array ('Passphrase' => 'sender_pwd')));
		$receiver = $this->gpg->genKey ($this->gpg->genKeyInput (array ('Passphrase' => 'receiver_pwd')));

		$encrypted = $this->gpg->encrypt ('Message to encrypt', $receiver->fingerprint, $sender->fingerprint, 'sender_pwd', true);
		$this->assertStartsWith ($encrypted->data, '-----BEGIN PGP MESSAGE-----');

		$res = $this->gpg->decrypt ($encrypted->data, 'receiver_pwd', $sender->fingerprint, True);
		$this->assert ($res->valid, 'Invalid sign');
		$this->assertEquals ($res->data, 'Message to encrypt');
	}
}


$test = new GpgTest ();
$test->run ();



