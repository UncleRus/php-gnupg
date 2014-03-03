#!/usr/bin/php5
<?php

abstract class Base
{

	public $field = array (
		'A' => 100,
		'B' => 200
	);
}


class C extends Base
{
	protected function _test ()
	{
		echo "TEST\n";
	}

	public function __construct ()
	{
		call_user_method ('_test', $this);
	}
}

var_dump (preg_split ('/\s+/', 'TEST'));

