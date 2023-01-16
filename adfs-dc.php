<?php
require('app/init/init-login.php');

// Gets the LDAP domain domain from the address bar
$logindomain = $_GET['ld'];

if(!isset($_GET['ld'])){
  //header('Location: adfs-domain.php');
}

// Gets the connection info from that LDAP domain
$adfsget = $db->prepare("SELECT * FROM `remind_adfs` WHERE `logindomain` = :logindomain");
$adfsget->execute([
  'logindomain' => $logindomain
]);
$adfs = $adfsget->rowCount() ? $adfsget : [];

$adfsgett = $db->prepare("SELECT * FROM `remind_adfs` WHERE `logindomain` = :logindomain");
$adfsgett->execute([
  'logindomain' => $logindomain
]);
$adfst = $adfsgett->rowCount() ? $adfsgett : [];

// Sets the connection info from that LDAP domain
foreach($adfs as $item){
  $dbadfsUrl = $item['adfsurl'];
  $spIdentifier = $item['spidentifier'];
  $db_domain = $item['domain'];
  $db_logo = $item['logo'];
}

if($adfsallow=='false'){
  header('Location: login.php');
}

?>

<?php

/**
 * Adfs Configuration.
 */
class AdfsConf {
    public $adfsUrl = 'https://adfs.hstly.net/adfs/ls/';
    //public $spIdentifier = 'urn:federation:remind-adfs-sso';
       
    /**
     * Content of the PEM certificate. If this certificate is protected by
     * password, you need to set encryptionCertPassword correctly.
     * 
     * If you provide certificate data, then it will ignore any value
     * configured for certificate path. 
     */
    public $encryptionCertData = '';
    
    /**
     *
     */
    public $encryptionCertPath = '';
    
    public $encryptionCertPassword = '';   
    
    protected static $_instance = NULL;

    /**
     * Prevent direct object creation
     */
    final private function  __construct() { }

    /**
     * Prevent object cloning
     */
    final private function  __clone() { }

    /**
     * Returns new or existing Singleton instance
     * @return Singleton
     */
    final public static function getInstance(){
        if(null !== self::$_instance){
            return self::$_instance;
        }
        self::$_instance = new AdfsConf();
        return self::$_instance;
    }
}
?>
<?php
/**
 * Handles the ADFS SignIn/SignOut/PRP handling.
 *  
 * @license http://www.gnu.org/licenses/gpl-2.0.html
 * 
 * Refer:
 *  http://code.google.com/p/simplesamlphp/source/browse/trunk/www/wsfed/sp/prp.php
 *  http://code.google.com/p/simplesamlphp/source/browse/trunk/www/wsfed/sp/initSSO.php
 *  http://code.google.com/p/simplesamlphp/source/browse/trunk/www/wsfed/sp/initSLO.php
 *  https://pamelaproject.com/svn/pw/pwcommon/trunk/vendorsrc/phpInfoCard/0.1.1-beta1/lib/rp.phpicprocessor.php
 */
//$adfsConf = 'https://adfs.hstly.net';
/*function redirectToAdfsSignInUrl($adfsConf, $context) {        
    header('Location: https://adfs.hstly.net/adfs/ls/?wa=wsignin1.0&wct='.gmdate('Y-m-d\TH:i:s\Z', time()).'&wtrealm=urn:federation:remind-adfs-sso&wctx=adfs-dc.php');
}*/

class AdfsBridge {
    
    function redirectToAdfsSignInUrl($adfsConf, $context) {        
        header('Location: '. $this->getAdfsSignInUrl($adfsConf, $context));
    }
    
    function redirectToAdfsSignOutUrl($adfsConf, $context) {        
        header('Location: '. $this->getAdfsSignOutUrl($adfsConf, $context));
    }
    
    function getAdfsSignInUrl($adfsConf, $context) {
        // used for the sign in url
        return
            /*$adfsConf->adfsUrl.
            '?wa=wsignin1.0'.
            '&wct='.gmdate('Y-m-d\TH:i:s\Z', time()).
            '&wtrealm='. $adfsConf->spIdentifier.
            '&wctx='. $context;*/
            $adfsConf->adfsUrl.'/adfs/ls/?wa=wsignin1.0&wct='.gmdate('Y-m-d\TH:i:s\Z', time()).'&wtrealm=urn:federation:remind-adfs-sso&wctx='. $context;
    }
    
    function getAdfsSignOutUrl($adfsConf, $context) {
        return
            $adfsConf->adfsUrl.
            '?wa=wsignout1.0'.
            '&wct='.gmdate('Y-m-d\TH:i:s\Z', time()).
            '&wtrealm='. $adfsConf->spIdentifier.
            '&wctx='. $context;
    }
    
    function getAdfsSignInResponse($adfsConf, $wa, $wresult, $wctx) {
        // TODO: Validate input
        
        // Validate configuration
        // If certificate content is provided, don't try to load from file.
        if ($adfsConf->encryptionCertData == '') {
            if ($adfsConf->encryptionCertPath != '') {
                $encryptionCertData = file_get_contents($adfsConf->encryptionCertPath);
                if($encryptionCertData === FALSE) {
                    throw new Exception('Unable to load certificate file \'' . $adfsConf->encryptionCertPath . '\'.');
                }
            }
        } else {
            $encryptionCertData = $adfsConf->encryptionCertData;
        }

	// Accommodate for MS-ADFS escaped quotes
	$wresult = str_replace('\"', '"', $wresult);
	
        // Load and parse the XML.
	$dom = new DOMDocument();
        $dom->loadXML(str_replace ("\r", "", $wresult));
	$xpath = new DOMXpath($dom);
	$xpath->registerNamespace('wst', 'http://schemas.xmlsoap.org/ws/2005/02/trust');
	$xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:1.0:assertion');
        $xpath->registerNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');
       
        // Decrypts the xmlToken if it is encrypted, using the private key specified in the configuration.
        $decryptedToken = '';
        $decryptionFailed = false;
        $rootElement = $xpath->query('/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/xenc:EncryptedData');
        $rootElement = $rootElement->item(0);
        if (preg_match('/EncryptedData/i', $rootElement->nodeName) > 0) {
            $topNode = $rootElement->firstChild;
            if (preg_match('/EncryptionMethod/i', $topNode->nodeName) > 0) {
                if ($blockAlgorithm=$topNode->getAttribute("Algorithm") ) {
                    switch ($blockAlgorithm) {
                        case "http://www.w3.org/2001/04/xmlenc#aes256-cbc":
                            $mcrypt_cipher = MCRYPT_RIJNDAEL_128;
                            $mcrypt_mode = MCRYPT_MODE_CBC;
                            $iv_length = 16;
                            break;
                        case "http://www.w3.org/2001/04/xmlenc#aes128-cbc":
                            $mcrypt_cipher = MCRYPT_RIJNDAEL_128;
                            $mcrypt_mode = MCRYPT_MODE_CBC;
                            $iv_length = 16;
                            break;
                        default:
                            throw new Exception("Unknown encryption blockAlgorithm: ".$blockAlgorithm.".");
                            break;
                    }
                    
                    # Alg. has been determined, check to make sure an error hasn't been thrown, and proceed.
                    if($decryptionFailed == false) {
                        $topNode = $topNode->nextSibling;
                        if(preg_match('/KeyInfo/i', $topNode->nodeName) > 0) {
                            $encryptionMethods = $topNode->getElementsByTagname("EncryptionMethod");
                            $encryptionMethod = $encryptionMethods->item(0);
                            $keyWrapAlgorithm = $encryptionMethod->getAttribute("Algorithm");
                            switch ($keyWrapAlgorithm) {
                                case "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p":
                                    $ssl_padding = OPENSSL_PKCS1_OAEP_PADDING;
                                    break;
                                case "http://www.w3.org/2001/04/xmlenc#rsa-1_5":
                                    $ssl_padding = OPENSSL_NO_PADDING;
                                    break;
                                default:
                                    throw new Exception("Unrecognized keyWrapAlgorithm: ".$keyWrapAlgorithm.".");
                                    break;
                            }
                            if ($decryptionFailed == false) {
                                if ($cipherValueNodes = $topNode->getElementsByTagname("CipherValue") ) {
                                    $cipherValueNode = $cipherValueNodes->item(0);
                                    $keyWrapCipher = $cipherValueNode->nodeValue;
                                    $keyWrapCipher = base64_decode($keyWrapCipher);
                                    $private_key=openssl_pkey_get_private($encryptionCertData, $adfsConf->encryptionCertPassword);
                                    if (!$private_key) {
                                        throw new Exception("Unable to load private key for decryption.");
                                    } else {
                                        if (openssl_private_decrypt($keyWrapCipher, $blockCipherKey, $private_key, $ssl_padding) ) {
                                            openssl_free_key($private_key);
                                            switch ($keyWrapAlgorithm) {
                                                case "http://www.w3.org/2001/04/xmlenc#rsa-1_5":
                                                    $blockCipherKey = substr($blockCipherKey, 2);
                                                    $keystart = strpos($blockCipherKey, 0) + 1;
                                                    $blockCipherKey = substr($blockCipherKey, $keystart);
                                                    break;
                                                default:
                                                    break;
                                            }
                                            $topNode = $topNode->nextSibling;
                                            if (preg_match('/CipherData/i', $topNode->nodeName) > 0) {
                                                if (!$cipherValueNodes = $topNode->getElementsByTagname("CipherValue")) {
                                                    throw new Exception("No block cipher data found.");
                                                } else {
                                                    $cipherValueNode = $cipherValueNodes->item(0);
                                                    $blockCipher = $cipherValueNode->nodeValue;
                                                    $blockCipher = base64_decode($blockCipher);

                                                    if ($iv_length > 0) {
                                                        $mcrypt_iv = substr($blockCipher, 0, $iv_length);
                                                        $blockCipher = substr($blockCipher, $iv_length);
                                                    }
                                                    // Decrypt and get the token.
                                                    $decryptedToken = mcrypt_decrypt($mcrypt_cipher, $blockCipherKey, $blockCipher, $mcrypt_mode, $mcrypt_iv);
                                                    if (!$decryptedToken) {
                                                        throw new Exception("Decryption of token failed.");
                                                    }
                                                }
                                            } else {
                                                throw new Exception("Unable to locate cipher data.");
                                            }
                                        } else {
                                            throw new Exception("Unable to decrypt token, check private key configuration.");
                                        }
                                    }
                                } else {
                                    throw new Exception("No wrapping cipher found.");
                                }
                            }
                        } else {
                            throw new Exception("Unable to continue, keyInfo is not present.");
                        }
                    }
                } else {
                    throw new Exception("Encryption method BlockAlgorithm not specified.");
                }
            } else {
                throw new Exception("Unable to determine Encryption method.");
            }
        } else {
            if(isset($encryptionCertData)) {
                throw new Exception("Unable to find encrypted data.");
            }
        }

        // Get saml:Assertion element
        if ($decryptedToken != '') {
            //set_error_handler('HandleXmlError');
            $decryptedToken_dom = new DOMDocument();
            $decryptedToken = str_replace('\"', '"', $decryptedToken);
            $decryptedToken = str_replace ("\r", "", $decryptedToken);   
            $xml_end_index = strrpos($decryptedToken, ">");
            $decryptedToken = substr($decryptedToken, 0, $xml_end_index + 1);
            $decryptedToken_dom->loadXML($decryptedToken);
            
            // Change the Xpath.
            $xpath = new DOMXpath($decryptedToken_dom);
            $xpath->registerNamespace('wst', 'http://schemas.xmlsoap.org/ws/2005/02/trust');
            $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:1.0:assertion');
            $xpath->registerNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');
            $assertion = $decryptedToken_dom->documentElement;
        } else {
            // Find the saml:Assertion element in the response.
            $assertions = $xpath->query('/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken/saml:Assertion');
            if ($assertions->length === 0) {
                throw new Exception('Received an ADFS response without an assertion.');
            }
            if ($assertions->length > 1) {
                throw new Exception('The WS-Fed PRP handler currently only supports a single assertion in a response.');
            }
            $assertion = $assertions->item(0);	
        }
        
	// Check time constraints of contitions (if present).
	foreach($xpath->query('./saml:Conditions', $assertion) as $condition) {
            $notBefore = $condition->getAttribute('NotBefore');
            $notOnOrAfter = $condition->getAttribute('NotOnOrAfter');
            if(!$this->checkCurrentTime($notBefore, $notOnOrAfter)) {
                throw new Exception('The WS-Fed response has expired.');
            }
	}

        // Create the user details response object.
        $userDetails = new AdfsUserDetails();
        
	// Extract the name identifier from the response.
	$nameid = $xpath->query('./saml:AuthenticationStatement/saml:Subject/saml:NameIdentifier', $assertion);
	if ($nameid->length === 0) {
            throw new Exception('Could not find the name identifier in the response from the WS-Fed.');
	}
        $userDetails->nameIdentifier = $nameid->item(0)->textContent;
        $userDetails->nameIdentifierFormat = $nameid->item(0)->getAttribute('Format');

	//*/ Extract the attributes from the response.
	$userDetails->attributes = array();
	$attributeValues = $xpath->query('./saml:AttributeStatement/saml:Attribute/saml:AttributeValue', $assertion);
	foreach($attributeValues as $attribute) {
            $name = $attribute->parentNode->getAttribute('AttributeName');
            $value = $attribute->textContent;
            if(!array_key_exists($name, $userDetails->attributes)) {
                $userDetails->attributes[$name] = array();
            }
            array_push($userDetails->attributes[$name], $value);
	}
        
        return $userDetails;
    }

    function handleXmlError($errno, $errstr, $errfile, $errline) {
        if ($errno==E_WARNING && (substr_count($errstr,"DOMDocument::loadXML()")>0)) {
            throw new DOMException($errstr);
        } else {
            return false;
        }
    }
    
    /**
     * checkCurrentTime is from simpleSAMLphp Utilities
     *
     * Check to verify that the current time is between
     * the specified start and end boundary
     *
     * @param string $start time in SAML2 format
     * @param string $end time in SAML2 format
     * @return boolean
     */
    function checkCurrentTime($start=NULL, $end=NULL) {
        $currentTime = time();

        if (!empty($start)) {
            $startTime = $this->parseSAML2Time($start);
            /* Allow for a 10 minute difference in Time */
            if (($startTime < 0) || (($startTime - 600) > $currentTime)) {
              return FALSE;
            }
        }
        if (!empty($end)) {
            $endTime = $this->parseSAML2Time($end);
            if (($endTime < 0) || ($endTime <= $currentTime)) {
              return FALSE;
            }
        }
        return TRUE;
    }
    
    /**
     * parseSAML2Time is from simpleSAMLphp Utilities
     *
     * This function converts a SAML2 timestamp on the form
     * yyyy-mm-ddThh:mm:ss(\.s+)?Z to a UNIX timestamp. The sub-second
     * part is ignored.
     *
     * Andreas comments:
     *  I got this timestamp from Shibboleth 1.3 IdP: 2008-01-17T11:28:03.577Z
     *  Therefore I added to possibliity to have microseconds to the format.
     * Added: (\.\\d{1,3})? to the regex.
     *
     *
     * @param string $time  The time to convert in SAML2 format
     * @return string  $time converted to a unix timestamp.
     */
    function parseSAML2Time($time) {
        $matches = array();

        /* We use a very strict regex to parse the timestamp. */
        if (preg_match('/^(\\d\\d\\d\\d)-(\\d\\d)-(\\d\\d)' .
                      'T(\\d\\d):(\\d\\d):(\\d\\d)(?:\\.\\d+)?Z$/D',
                      $time, $matches) == 0) {
        throw new Exception(
                'Invalid SAML2 timestamp passed to' .
                ' parseSAML2Time: ' . $time);
        }

        /* Extract the different components of the time from the
         * matches in the regex. intval will ignore leading zeroes
         * in the string.
         */
        $year = intval($matches[1]);
        $month = intval($matches[2]);
        $day = intval($matches[3]);
        $hour = intval($matches[4]);
        $minute = intval($matches[5]);
        $second = intval($matches[6]);

        /* We use gmmktime because the timestamp will always be given
         * in UTC.
         */
        $ts = gmmktime($hour, $minute, $second, $month, $day, $year);

        return $ts;
    }
}
?>
<?php
/**
 * Description of adfsuserdetails
 */
class AdfsUserDetails {
    
    public $nameIdentifier;
    
    public $nameIdentifierFormat;
    
    public $attributes;
}
?>

<!DOCTYPE html>
<html>

  <head>
    <title>Login</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta content="text/html; charset=UTF-8; X-Content-Type-Options=nosniff" http-equiv="Content-Type" />

    <!--Scripts-->
    <link href="app/fa/css/all.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css?family=Montserrat" rel="stylesheet">
    <link rel="preconnect" href="https://fonts.gstatic.com">
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@300;400;500&display=swap" rel="stylesheet">
  </head>
  <body>
    <div class="main">
      <div class="overlay-color">
        <div class="container">
          
          <div class="row">
            <div class="column left">
              <div class="left-content">
              </div>
            </div>
            
            <div class="column right">
              <div class="login-container">
                <div class="login-form">

                    <img src="<?php echo $db_logo; ?>" style="height:50px;width:auto;">

                    <h2 class="maintxt">Sign in</h2>

                    <br>

                    <div class="adfslogin">
                      <?php if(!isset($_SESSION['AdfsUserDetails'])) : ?>               
                      <?php else : ?>
                        <?php
                          // Show User ID and attributes.
                          $userDetails = unserialize($_SESSION['AdfsUserDetails']);         
                          $userEmail = $userDetails->nameIdentifier;  
                          echo $userEmail;






                                $dbusr = "SELECT * FROM `passwordlogin` WHERE `username` = '$userEmail' AND `recovery` = 'ADFS'";
                                $conusr = $conn->query($dbusr);
                                $usrct = mysqli_num_rows($conusr);

                                if($usrct=='1'){
                                  // What to do is the user is in the DB

                                  // Gets the info from the DB
                                  $inforget = $db->prepare("SELECT * FROM `passwordlogin` WHERE `username` = :username AND `recovery` = 'ADFS'");
                                  $inforget->execute([
                                    'username' => $userEmail
                                  ]);
                                  $userinfo = $inforget->rowCount() ? $inforget : [];
  
                                  foreach($userinfo as $item){
                                    $usrtoken = $item['token'];

                                    // Assigned the session as the username/account email
                                    $_SESSION["suite"] = $userEmail;

                                    // Gets the cookie and encrypts it
                                    $token_cookie = base64_encode(openssl_encrypt($usrtoken, $method, $key, OPENSSL_RAW_DATA, $iv));
                                    setcookie('token',$token_cookie,time()+2678400); // 86400 = 1 day, 2678400 = 31 days

                                    // Regenerates the session code
                                    session_regenerate_id(true);

                                    // Sends the user to the app
                                    header('Location: app/index.php');
                                
                                    // Makes log query
                                    $logQuery = $db->prepare("
                                      INSERT INTO remind_log (account, content, ip, date)
                                      VALUES (:account, :content, :ip, :date)
                                    ");
                                    $content = 'Successful login ADFS';
                                    $logQuery->execute([
                                      ':account' => $item['accountid'],
                                      ':content' => $content,
                                      ':ip' => $usrwanip,
                                      ':date' => $logdate
                                    ]);
                                  }
                                }else{
                                  // What to do is the LDAP user isn't in the DB
                                  
                                  // For the accountid
                                  $accountlength = 16;
                                  function getAcc($lengthCode) {
                                    $characters = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
                                    $randomString = '';
                                    for ($i = 0; $i < $lengthCode; $i++) {
                                      $index = rand(0, strlen($characters) - 1);
                                      $randomString .= $characters[$index];
                                    }
                                    return $randomString;
                                  }
                                  $accountid = getAcc($accountlength);

                                  // Generates a token for each user signed up
                                  /*$nlength=100; 
                                  function getName($nlength) { 
                                    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'; 
                                    $randomString = ''; 
                                    for ($i = 0; $i < $nlength; $i++) { 
                                      $index = rand(0, strlen($characters) - 1); 
                                      $randomString .= $characters[$index]; 
                                    } 
                                    return $randomString; 
                                  } 
                                  $token = getName($nlength); */
                                  $str = rand();
                                  $token = hash("sha256", $str);

                                  $strtwo = rand();
                                  $identifier = hash("sha256", $strtwo);

                                  // Insets everything into the database
                                  $query = "INSERT INTO passwordlogin(accountid, firstname, lastname, username, password, recovery, preminum, token, identifier, ldapdomain) VALUES('$accountid', '$userFN','$userLN','$userEmail', 'ADFS', 'ADFS','false','$token','$identifier', '$logindomain')";
                                  if (mysqli_query($connect, $query)) {
                                    // The code that runs if the registration is successful
                                    //echo ("<p style='color: green;'>Account synced. Please login again.</p>");  
                                    $usrtoken = $token;

                                    // Assigned the session as the username/account email
                                    $_SESSION["suite"] = $userEmail;

                                    // Gets the cookie and encrypts it
                                    $token_cookie = base64_encode(openssl_encrypt($usrtoken, $method, $key, OPENSSL_RAW_DATA, $iv));
                                    setcookie('token',$token_cookie,time()+2678400); // 86400 = 1 day, 2678400 = 31 days

                                    // Regenerates the session code
                                    session_regenerate_id(true);

                                    // Sends the user to the app
                                    header('Location: app/index.php');
                                    
                                    $logQuery = $db->prepare("
                                      INSERT INTO remind_log (account, content, ip, date)
                                      VALUES (:account, :content, :ip, :date)
                                    ");
                                    $content = 'New ADFS user created (Email: '.$userEmail.')';
                                    $logQuery->execute([
                                      ':account' => $accountid,
                                      ':content' => $content,
                                      ':ip' => $usrwanip,
                                      ':date' => $logdate
                                    ]);
                                  } 
                                }









                          //htmlShowArray($userDetails->attributes);
                        ?>
                      <?php endif; ?>
<? ob_start(); ?>
<?php
    if(!isset($_SESSION)) {
        session_start();
    }
?>

<?php if(!isset($_REQUEST['authaction'])) : ?>
    <?php if(!isset($_SESSION['AdfsUserDetails'])) : ?>
        <form action="adfs-dc.php" method="post" name="login" id="form-login">
            <input type="submit" name="Submit" class="button" value="Log in" />
            <input type="text" style="display:none;" name="sso" value="<?php echo $dbadfsUrl; ?>" />
            <input type="hidden" name="authaction" value="Login" />
        </form>
    <?php else : ?>
        <form action="adfs-dc.php" method="post" name="logout" id="form-logout">
            <input type="submit" name="Submit" class="button" value="Log out" />
            <input type="hidden" name="authaction" value="Logout" />
        </form>
    <?php endif; ?>
<?php else : ?>
    <?php 
        if($_REQUEST['authaction'] == 'Login'){
            // Redirect to ADFS for Sign In.

            //$adurl = $dbadfsUrl;
            //$adurl = 'https://adfs.hstly.net/adfs/ls/';
            //$adfs = new AdfsBridge();
            //$adfs->redirectToAdfsSignInUrl(AdfsConf::getInstance(), 'adfs-dc.php');
            $post = $_POST['sso'];
            header('Location: '.$post.'?wa=wsignin1.0&wct='.gmdate('Y-m-d\TH:i:s\Z', time()).'&wtrealm=urn:federation:remind-adfs-sso&wctx=adfs-dc.php');
            //header('Location: '.$dbadfsUrl.'?wa=wsignin1.0&wct='.gmdate('Y-m-d\TH:i:s\Z', time()).'&wtrealm=urn:federation:remind-adfs-sso&wctx=adfs-dc.php');
        }
        ?>
    <?php if($_REQUEST['authaction'] == 'Logout') : ?>
        <?php
            // Clear session and redirect to home page.
            unset($_SESSION['AdfsUserDetails']);
            header('Location: adfs-dc.php');
        ?>
    <?php endif; ?>
<?php endif; ?>
<? ob_flush(); ?>


<?php if(!isset($_REQUEST['wa'])) : ?>
<?php else : ?>
    <?php if($_REQUEST['wa'] == 'wsignin1.0') : ?>
        <?php 
            $adfs = new AdfsBridge();
            try {
                $userDetails = $adfs->getAdfsSignInResponse(
                                AdfsConf::getInstance(),
                                $_REQUEST['wa'],
                                $_REQUEST['wresult'],
                                $_REQUEST['wctx']);

                // Set the user details in session.
                $_SESSION['AdfsUserDetails'] = serialize($userDetails);
                // Expect return url in wctx (set by authform.php)
                //header('Location: '. $_REQUEST['wctx']);
                header('Location: adfs-dc.php');
            } catch (Exception $e) {
                printf('Message: '.$e->getMessage());
            }
        ?>
    <?php endif; ?>
    <?php if($_REQUEST['wa'] == 'wsignout1.0') : ?>
        <?php
            if (isset($_SESSION['AdfsUserDetails'])) {
                unset($_SESSION['AdfsUserDetails']);
            }            
            exit;
        ?>
    <?php endif; ?>
<?php endif; ?>
                    </div>

                    <br><br><br><br>

                    <p>Please login with your Active Directory/LDAP account provided to you by your admin.</p>
                    <p>If you forgot your password, please contact your domain admin.</p>
                    <p>Accounts managed by: <?php echo $db_domain; ?></p>

                </div>
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>
  </body>
</html>
<style>
.button {
    background: #5460fe;
    color: #fff;

    padding: 7px;

    outline: none;
    border-radius: 5px;
    border: none;
    
    cursor: pointer;

    width: 100px;
}
<?php include('landing/login-v2.css'); ?>
</style>