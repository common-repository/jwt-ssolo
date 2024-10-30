<?php
function jwtl_my_encrypt($data, $key) {
    // Remove the base64 encoding from our key
    $encryption_key = base64_decode($key);
    // Generate an initialization vector
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
    // Encrypt the data using AES 256 encryption in CBC mode using our encryption key and initialization vector.
    $encrypted = openssl_encrypt($data, 'aes-256-cbc', $encryption_key, 0, $iv);
    // The $iv is just as important as the key for decrypting, so save it with our encrypted data using a unique separator (::)
    return base64_encode($encrypted . '::' . $iv);
}

function jwtl_my_decrypt($data, $key) {
    // Remove the base64 encoding from our key
    $encryption_key = base64_decode($key);
    // To decrypt, split the encrypted data from our IV - our unique separator used was "::"
    list($encrypted_data, $iv) = explode('::', base64_decode($data), 2);
    return openssl_decrypt($encrypted_data, 'aes-256-cbc', $encryption_key, 0, $iv);
}





function jwtl_GetLogin($login,$password){
    $pars=array(
        'login' => $login,
        'password' => $password
        
    );
    $pars=json_encode($pars);
    //step1
    
    $args = array( 'headers' => array( 'Content-Type' => 'application/json' ), 'body' => $pars );
    $datat = wp_remote_post('https://auth.ssolo.co.uk/api/v1/login.php',$args);
    $response_code = wp_remote_retrieve_response_code( $datat );
    $response_body = wp_remote_retrieve_body( $datat );
    if ( !in_array( $response_code, array(200,201) ) || is_wp_error( $response_body ) )
        return false;
        $data = json_decode( $response_body, true );
        
        
        
        $token=jwtl_my_decrypt($data['data']['token'],$data['data']['secret']);
        $vtoken=explode("|",$token);
        setcookie("tokenstatus", $vtoken[0], time() + (86400 * 30), "/");
        setcookie("token",$data['data']['token'],time() + (86400 * 30), "/");
        setcookie("secret",$data['data']['secret'],time() + (86400 * 30), "/");
        
        return $data;
        
        
}

function jwtl_AddAccount ($account) { # $account is an array with the follow data:
    # login
    # name
    # surname
    # email
    # phone
    # mobile
    # address_line1
    # address_line2
    # zip
    # city
    # region
    # country
    # password
    $token=$_COOKIE['token'];
    
    
    //step2
    $pars=array(
    "login" => $account[0],
    "name" => $account[1],
    "surname" => $account[2],
    "email" => $account[3],
    "phone" => $account[4],
    "mobile" => $account[5],
    "address_line1" => $account[6],
    "address_line2" => $account[7],
    "zip" => $account[8],
    "city" => $account[9],
    "region" => $account[10],
    "country" => $account[11],
    "password" => $account[12]
    );
    
    $pars=json_encode($pars);
    $headers = array();
    $headers[] = "authorization: Bearer " . $token;
    
    $args = array( 'headers' => array( $header ), 'body' => $pars );
    $datat = wp_remote_post('https://auth.ssolo.co.uk/api/v1/login.php',$args);
    $response_code = wp_remote_retrieve_response_code( $datat );
    $response_body = wp_remote_retrieve_body( $datat );
    if ( !in_array( $response_code, array(200,201) ) || is_wp_error( $response_body ) )
        return false;
        $result = json_decode( $response_body, true );
        
        return $result;
}


//function getJwt($fields = array(), $secretkey = NULL) {

//	$encoded_header = base64_encode('{"alg":"RS256","typ":"JWT"}');

//	$encoded_payload = base64_encode(json_encode($fields));

//	$header_payload = $encoded_header . '.' . $encoded_payload;

//	$signature = base64_encode(hash_hmac('SHA256', $header_payload, $secretkey, true));

//	$jwt_token = $header_payload . '.' . $signature;

//	return $jwt_token;

//}

function jwtl_getJwt($fields = array(), $secretkey = NULL) {
    $jwt_token=jwt_encode($fields, $secretkey, 'RS256');
    return $jwt_token;
    
}

function jwtl_checkJwt($token = NULL, $secretkey = NULL) {
    
    $jwt_values = explode('.', $token);
    
    $recieved_signature = $jwt_values[2];
    
    $recievedHeaderAndPayload = $jwt_values[0] . '.' . $jwt_values[1];
    
    $resultedsignature = base64_encode(hash_hmac('RS256', $recievedHeaderAndPayload, $secretkey, true));
    
    if ($resultedsignature == $recieved_signature) return(true);
    else return(false);
    
}




function jwtl_ModAccount ($array) {
    # $account is an array with the follow data:
    # login
    # name
    # surname
    # email
    # phone
    # mobile
    # address_line1
    # address_line2
    # zip
    # city
    # region
    # country
    # password
    $token=$_COOKIE['token'];
    
    $curlSES=curl_init();
    //step2
    $pars=array(
    "login" => $account[0],
    "name" => $account[1],
    "surname" => $account[2],
    "email" => $account[3],
    "phone" => $account[4],
    "mobile" => $account[5],
    "address_line1" => $account[6],
    "address_line2" => $account[7],
    "zip" => $account[8],
    "city" => $account[9],
    "region" => $account[10],
    "country" => $account[11],
    "password" => $account[12]
    );
    
    $pars=json_encode($pars);
    
    
    
    $headers = array();
    $headers[] = "authorization: Bearer " . $token;
    
    //step4
    curl_close($curlSES);
    $args = array( 'headers' => array( $header ), 'body' => $pars );
    $datat = wp_remote_post('https://auth.ssolo.co.uk/api/v1/moduser.php',$args);
    $response_code = wp_remote_retrieve_response_code( $datat );
    $response_body = wp_remote_retrieve_body( $datat );
    if ( !in_array( $response_code, array(200,201) ) || is_wp_error( $response_body ) )
        return false;
        $return = json_decode( $response_body, true );
        
        
        return $result;
}

function jwtl_DelAccount ($token,$user_id) {
    $data=explode("|",$token);
    $secret=$data[1];
    $isadmin=$data[2];
    if ( $user_id == '' or !$user_id) {
        $user_id=$data[5];
    }
    
    
    //step2
    $pars=array(
    "user_id" => $user_id
    );
    $pars=json_encode($pars);
    $headers = array();
    $headers[] = "authorization: Bearer " . $token;
    
    $args = array( 'headers' => array( $header ), 'body' => $pars );
    $datat = wp_remote_post('https://auth.ssolo.co.uk/api/v1/deluser.php',$args);
    $response_code = wp_remote_retrieve_response_code( $datat );
    $response_body = wp_remote_retrieve_body( $datat );
    if ( !in_array( $response_code, array(200,201) ) || is_wp_error( $response_body ) )
        return false;
        $return = json_decode( $response_body, true );
        
        
        return $result;
        
}

function jwtl_BlockAccount ($token,$user_id) {
    $data=explode("|",$token);
    $secret=$data[1];
    $isadmin=$data[2];
    if ( $user_id == '' or !$user_id) {
        $user_id=$data[5];
    }
    
    
    //step2
    $pars=array(
    "user_id" => $user_id
    );
    $pars=json_encode($pars);
    $headers = array();
    $headers[] = "authorization: Bearer " . $token;
    
    $args = array( 'headers' => array( $header ), 'body' => $pars );
    $datat = wp_remote_post('https://auth.ssolo.co.uk/api/v1/blockuser.php',$args);
    $response_code = wp_remote_retrieve_response_code( $datat );
    $response_body = wp_remote_retrieve_body( $datat );
    if ( !in_array( $response_code, array(200,201) ) || is_wp_error( $response_body ) )
        return false;
        $return = json_decode( $response_body, true );
        
        return $result;
        
        
        
}

function jwtl_UnBlockAccount ($token,$user_id) {
    $data=explode("|",$token);
    $secret=$data[1];
    $isadmin=$data[2];
    if ( $user_id == '' or !$user_id) {
        $user_id=$data[5];
    }
    
    
    //step2
    $pars=array(
    "user_id" => $user_id
    );
    $pars=json_encode($pars);
    $headers = array();
    $headers[] = "authorization: Bearer " . $token;
    
    $args = array( 'headers' => array( $header ), 'body' => $pars );
    $datat = wp_remote_post('https://auth.ssolo.co.uk/api/v1/unblockuser.php',$args);
    $response_code = wp_remote_retrieve_response_code( $datat );
    $response_body = wp_remote_retrieve_body( $datat );
    if ( !in_array( $response_code, array(200,201) ) || is_wp_error( $response_body ) )
        return false;
        $return = json_decode( $response_body, true );
        
        return $result;
        
}

function jwtl_CheckToken ($token,$user_id) {
    # the CheckToken function perform a token validity check on AUTH server
    
    //step2
    $pars=array(
    "userid" => $user_id
    );
    $pars=json_encode($pars);
    $headers = array();
    $headers[] = "authorization: Bearer " . $token;
    
    $args = array( 'headers' => array( $header ), 'body' => $pars );
    $datat = wp_remote_post('https://auth.ssolo.co.uk/api/v1/checktoken.php',$args);
    $response_code = wp_remote_retrieve_response_code( $datat );
    $response_body = wp_remote_retrieve_body( $datat );
    if ( !in_array( $response_code, array(200,201) ) || is_wp_error( $response_body ) )
        return false;
        $return = json_decode( $response_body, true );
        
        return $result;
        
}

function jwtl_ValidateToken($token,$secret) {
    $token=jwtl_my_decrypt($token,$secret);
    $vtoken=explode("|",$token);
    if ( $vtoken[0] == "valid") {
        return $vtoken;
    } else {
        $vtoken[0]="invalid";
        return $vtoken;
    }
}


?>
