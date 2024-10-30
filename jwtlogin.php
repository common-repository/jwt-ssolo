<?php
include_once 'config.php';
/*
 Plugin Name: JWT SSOLO plugin
 Version: 1.5.2
 Description: AUth2 authentication
 Author: SSOLO ltd
 Author URI: http://auth.ssolo.co.uk
 */

//ini_set('display_errors', 1);
//ini_set('display_startup_errors', 1);
//error_reporting(E_ALL);

// this action is executed just before the invocation of the WordPress authentication process
define( "JWTL_MY_PLUGIN_PATH", plugin_dir_path( __FILE__ ) );

add_action('wp_authenticate','jwtl_checkTheUserAuthentication');

function jwtl_checkTheUserAuthentication() {
  
    
    
    include(ABSPATH . "wp-includes/pluggable.php");
    if (isset($_POST['log']) and !isset($_COOKIE[$user_id]) and !is_admin()) {
    $username=sanitize_email($_POST['log']);
    $password=sanitize_text_field($_POST['pwd']);

    
    $response = jwtl_GetLogin($username,$password);
   
  
    $valid=jwtl_ValidateToken($response['data']['token'],$response['data']['secret']);
 
  
 
  
    // try to log into the external service or database with username and password
    //$ext_auth = try2AuthenticateExternalService($username,$password);
    
    // if external authentication was successful
    if( $valid[0]  == "invalid" ) {
        // User does not exist,  send back an error message
        $user = new WP_Error( 'denied', __("ERROR: User/pass bad") );
        
    } else {
        
        
        $userobj = new WP_User();
        $user = $userobj->get_data_by( 'email', $username ); // Does not return a WP_User object :(
        $user = new WP_User($user->ID,$username,$user->ID); // Attempt to load up the user with that ID
        
        if( $user->ID == 0 ) {
            // The user does not currently exist in the WordPress user table.
            // You have arrived at a fork in the road, choose your destiny wisely
            
            // If you do not want to add new users to WordPress if they do not
            // already exist uncomment the following line and remove the user creation code
            #$user = new WP_Error( 'denied', __("ERROR: Not a valid user for this system") );
            
            
            
            // Setup the minimum required user information for this example
            $userdata = array( 'user_email' => $username,
            'user_login' => $username,
            'first_name' => $valid[1],
            'last_name' => $valid[2]
            );
            
            $new_user_id = wp_insert_user( $userdata ); // A new user has been created
            
            // Load the new user info
            #$user = new WP_User ($new_user_id);
        }
        
        // find a way to get the user id
        $user_id = username_exists($username);
        // userdata will contain all information about the user
        $userdata = get_userdata($user_id);
        $user = set_current_user($user_id,$username);
        
        // this will actually make the user authenticated as soon as the cookie is in the browser
        wp_set_auth_cookie($user_id);
        // the wp_login action is used by a lot of plugins, just decide if you need it
        do_action('wp_login',$userdata->ID);
        
        // you can redirect the authenticated user to the "logged-in-page", define('MY_PROFILE_PAGE',1); f.e. first
        header("Location:".get_page_link(MY_PROFILE_PAGE));
    }
    }
}
// redirect for registration and lost password

function jwtl_disable_tml_registration( $action ) {
    if ( 'register' == $action ) {
        tml_unregister_action( $action );
    }
}
add_action( 'tml_registered_action', 'jwtl_disable_tml_registration' );


function jwtl_disable_tml_password_recovery( $action ) {
    if ( in_array( $action, array( 'lostpassword', 'resetpass' ) ) ) {
        tml_unregister_action( $action );
    }
}
add_action( 'tml_registered_action', 'jwtl_disable_tml_password_recovery' );

function jwtl_passurl_wpse_208054($lostpassword_url, $redirect ) {
    include "config.php";
    return 'https://auth.ssolo.co.uk/forgotpwd.php?servercode='.$servercode;
}
add_filter('lostpassword_url', 'jwtl_passurl_wpse_208054', 10, 2);

add_action( 'show_user_profile', 'jwtl_extra_user_profile_fields' );
add_action( 'edit_user_profile', 'jwtl_extra_user_profile_fields' );

function jwtl_extra_user_profile_fields( $user ) { 
include "config.php";
    ?>
    <h3><?php _e("Auth profile informations"); ?> </h3>
    
    <table class="form-table">
    <tr>
    <th><label for="getuserinfo"><?php _e("Modify user"); ?></label></th>
    <td>
    <button type="button"  class="button wp-generate-pw hide-if-no-js" onclick="location.href = 'https://auth.ssolo.co.uk/moduser.php?servercode=<?php echo $servercode ?>'">Modify User data</button>
    </td>
    </tr>
    <tr>
    <th><label for="delaccount"><?php _e("Delete Account"); ?></label></th>
    <td>
    <button type="button" class="button wp-generate-pw hide-if-no-js" onclick="location.href = 'https://auth.ssolo.co.uk/deleteaccount.php?servercode=<?php echo $servercode ?>'">Delete User account</button>
    </td>
    </tr>
    </table>
<?php   
}



class jwtl_Getconfig {
    private $getconfig_options;
    
    public function __construct() {
        add_action( 'admin_menu', array( $this, 'getconfig_add_plugin_page' ) );
        add_action( 'admin_init', array( $this, 'getconfig_page_init' ) );
    }
    
    public function getconfig_add_plugin_page() {
        add_menu_page(
            'JWT-getconfig', // page_title
            'JWT-getconfig', // menu_title
            'manage_options', // capability
            'jwt-getconfig', // menu_slug
            array( $this, 'getconfig_create_admin_page' ), // function
            'dashicons-admin-generic', // icon_url
            3 // position
            );
    }
    
    public function getconfig_create_admin_page() {
        include "config.php";
        $this->getconfig_options = get_option( 'getconfig_option_name' ); 

if ( is_admin() ) {
    $getconfig_options = get_option( 'getconfig_option_name' ); // Array of All Options
    $login_0 = $getconfig_options['login_0']; // Login
    $password_1 = $getconfig_options['password_1']; // Password
    if ( !$login_0 or !$password_1) {
        $noconf=1;
        echo "<center><h3>Missing configuration</h3></center>";
    } 
		echo "<div class=\"wrap\">";
	    echo "<h2>JWT SSOLO getconfig</h2><br>";
	    if ( $noconf != 1 ) {
		echo "<p>Your servercode is;<b> $servercode </b> Operation token: Registered</p>";
	    }
		settings_errors();

		echo "<form method=\"post\" action=\"options.php\">";
				
					settings_fields( 'getconfig_option_group' );
					do_settings_sections( 'getconfig-admin' );
					submit_button();
			
			echo "</form>";
		echo "</div>";
    }
	 }
    
	public function getconfig_page_init() {
		register_setting(
			'getconfig_option_group', // option_group
			'getconfig_option_name', // option_name
			array( $this, 'getconfig_sanitize' ) // sanitize_callback
		);

		add_settings_section(
			'getconfig_setting_section', // id
			'Settings', // title
			array( $this, 'getconfig_section_info' ), // callback
			'getconfig-admin' // page
		);

		add_settings_field(
			'login_0', // id
			'Login', // title
			array( $this, 'login_0_callback' ), // callback
			'getconfig-admin', // page
			'getconfig_setting_section' // section
		);

		add_settings_field(
			'password_1', // id
			'Password', // title
			array( $this, 'password_1_callback' ), // callback
			'getconfig-admin', // page
			'getconfig_setting_section' // section
		);
	}

	public function getconfig_sanitize($input) {
		$sanitary_values = array();
		if ( isset( $input['login_0'] ) ) {
			$sanitary_values['login_0'] = sanitize_text_field( $input['login_0'] );
		}

		if ( isset( $input['password_1'] ) ) {
			$sanitary_values['password_1'] = sanitize_text_field( $input['password_1'] );
		}

		return $sanitary_values;
	}

	public function getconfig_section_info() {
		
	}

	public function login_0_callback() {
		printf(
			'<input class="regular-text" type="text" name="getconfig_option_name[login_0]" id="login_0" value="%s">',
			isset( $this->getconfig_options['login_0'] ) ? esc_attr( $this->getconfig_options['login_0']) : ''
		);
	}

	public function password_1_callback() {
		printf(
			'<input class="regular-text" type="password" name="getconfig_option_name[password_1]" id="password_1" value="%s">',
			isset( $this->getconfig_options['password_1'] ) ? esc_attr( $this->getconfig_options['password_1']) : ''
		);
	}

}
if ( is_admin() ) {
    $getconfig_options = get_option( 'getconfig_option_name' ); // Array of All Options
    $login_0 = $getconfig_options['login_0']; // Login
    $password_1 = $getconfig_options['password_1']; // Password
    if ( !$login_0 or !$password_1) {
        echo "<h3><center>JWT AUTH Configuration not present, please login to download your server configuration</center></h3><br>";
        echo "<center>Click on JWT getconfig item menu and insert your login and password for SSOLO AUTH server</center>";
    } else {
    $response = jwtl_GetLogin( $login_0,$password_1 );
 
    $valid=jwtl_ValidateToken($response['data']['token'],$response['data']['secret']);
  
    // if external authentication was successful
    if( $valid[0]  == "invalid" ) {
        // User does not exist,  send back an error message
        echo "<div class=\"w3-container\">";
        echo "<h3>AUTH get config</h3>";
        echo "<b>Error: Login invalid</b><br><br>";
        $user = new WP_Error( 'denied', __("ERROR: User/pass bad") );
        echo "<button class=\"w3-btn w3-blue-grey\" onclick=\"goBack()\">Go Back</button>";
        echo "</div>";
        
        echo "<script>";
        echo "function goBack() {";
        echo "    window.history.back();";
        echo "}";
        echo "</script>";
        
    } else {
        $my_plugin = plugin_dir_path( __FILE__ );
      
        $servercode=$valid[6];
        $token=$response['data']['token'];
        $userid=$valid[5];
        
        $myfile = fopen($my_plugin."config.php", "w") or die("Unable to open file!");
        $txt = "<?php\n";
        fwrite($myfile, $txt);
        $txt = "\$servercode=\"".$servercode."\";\n";
        fwrite($myfile, $txt);
        $txt = "\$token=\"".$token."\";\n";
        fwrite($myfile, $txt);
        $txt = "\$user_id=\"".$userid."\";\n";
        fwrite($myfile, $txt);
        $txt = "?>\n";
        fwrite($myfile, $txt);
        fclose($myfile);
     
        
    }
    }
	$getconfig = new jwtl_Getconfig();
}
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
