<?php
// Dependencies
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception as MailerException;

require 'mailer/src/Exception.php';
require 'mailer/src/PHPMailer.php';
require 'mailer/src/SMTP.php';
// defaults
$template = 'home';
$db_connection = 'sqlite:..\private\users.db';
$configuration = array(
    '{FEEDBACK}'          => '',
    '{LOGIN_LOGOUT_TEXT}' => 'Identificar-me',
    '{LOGIN_LOGOUT_URL}'  => '/?page=login',
    '{METHOD}'            => 'POST', // es veuen els paràmetres a l'URL i a la consola (???)
    '{REGISTER_URL}'      => '/?page=register',
    '{VERIFICATION_URL}'      => '/?page=verification',
    '{RESET_PASSWORD_URL}'      => '/?page=reset_password',
    '{RECOVERY_URL}'      => '/?page=recovery',
    '{SEND_RECOVERY_MAIL}'      => '/?page=send_recovery',
    '{2FA_URL}'      => '/?page=2FA',
    '{SITE_NAME}'         => 'La meva pàgina'
);
// parameter processing


function sendMail($body, $username, $address){
        $mail = new PHPMailer();
        $mail->IsSMTP();
        $mail->SMTPAuth = true;
        $mail->SMTPSecure = "ssl";
        $mail->Host = "smtp.gmail.com";
        $mail->Port = 465;
        $mail->Username = "[algo@gmail.com]";
        $mail->Password = "[password]";
        $mail->SetFrom('[algo@gmail.com]', 'Joan Tiscar');
        $mail->AddReplyTo("[algo@gmail.com]","Joan Tiscar");
        $mail->Subject = "Confirmació del compte";
        $mail->MsgHTML($body);
        $mail->AddAddress($address, $username);
        if(!$mail->Send()) {
            echo "Error al enviar: " . $mail->ErrorInfo;
        }

}

$parameters = [];
if  ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $parameters = $_POST;
}else if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $parameters = $_GET;
}
if (isset($parameters['page'])) {
    if ($parameters['page'] == 'register') {
        $template = 'register';
        $configuration['{REGISTER_USERNAME}'] = '';
        $configuration['{LOGIN_LOGOUT_TEXT}'] = 'Ja tinc un compte';
    } else if ($parameters['page'] == 'login') {
        $token_used = false;
        if (isset ($_COOKIE['session_token'])) {
            $db = new PDO($db_connection);
            $sql = 'SELECT * FROM users WHERE user_name = :user_name and session_token = :session_token';
            $query = $db->prepare($sql);
            $query->bindValue(':user_name', $_COOKIE['session_user']);
            $query->bindValue(':session_token', $_COOKIE['session_token']);
            $query->execute();
            $result_row = $query->fetchObject();
            if ($result_row) {
                $configuration['{FEEDBACK}'] = '"Sessió" iniciada com <b>' . htmlentities($_COOKIE['session_user']) . '</b>';
                $configuration['{LOGIN_LOGOUT_TEXT}'] = 'Tancar "sessió"';
                $configuration['{LOGIN_LOGOUT_URL}'] = '/?page=logout';
                $token_used = true;
            }
        }
        if (!$token_used) {
            $template = 'login';
            $configuration['{LOGIN_USERNAME}'] = '';
        }
    } else if ($parameters['page'] == 'logout') {
        setcookie ('session_user', '', time() - 3600);
        setcookie ('session_token', '', time() - 3600);
    } else if ($parameters['page'] == '2FA'){
        $template = '2FA';
        $configuration['{LOGIN_USERNAME}'] = $parameters['user_name'];
    } else if ($parameters['page'] == 'verification'){
        $db = new PDO($db_connection);
        $sql = 'UPDATE users SET  verified = 1, verification_token = null WHERE verification_token = :verification_token';
        $query = $db->prepare($sql);
        $query->bindValue(':verification_token', $parameters['verification_token']);
        $query->execute();
        if ($query->rowCount() > 0) {
            $configuration['{FEEDBACK}'] = 'S\'ha verificat el compte. Ja pots iniciar sessió';
        } else {
            $configuration['{FEEDBACK}'] = '<mark>ERROR: El enllaç de validació ha expirat o l\'usuari ja ha sigut validat\'</mark>';
        } 

    } else if ($parameters['page'] == 'recovery'){
        $template = 'recovery';
        
    } else if ($parameters['page'] == 'reset_password'){
        $db = new PDO($db_connection);
        $sql = 'SELECT * FROM users WHERE  verification_token = :verification_token';
        $query = $db->prepare($sql);
        $query->bindValue(':verification_token', $parameters['verification_token']);
        $query->execute();
        $result_row = $query->fetchObject();
        if ($result_row) {
            $template = 'reset_password';
            $configuration['{USER_NAME}'] =$result_row->user_name;
            $configuration['{VERIFICATION_TOKEN}'] = $parameters['verification_token'];
        } else {
            $configuration['{FEEDBACK}'] = '<mark>ERROR: El enllaç de validació ha expirat o l\'usuari ja ha reiniciat la seva contrasenya</mark>';
        } 
    
    } 
}else if (isset($parameters['register'])) {
    $db = new PDO($db_connection);
    $sql = 'INSERT INTO users (user_name, user_password, user_mail, verification_token) VALUES (:user_name, :user_password, :user_mail, :verification_token)';
    $query = $db->prepare($sql);
    $query->bindValue(':user_name', $parameters['user_name']);
    $query->bindValue(':user_mail', $parameters['user_mail']);
    $verificationToken = hash_pbkdf2('sha512', $parameters['user_name'], time(), 1000, 100, false);
    $query->bindValue(':user_password', hash_pbkdf2('sha512', $parameters['user_password'], $parameters['user_name'], 1000, 254, false) );
    $query->bindValue(':verification_token', $verificationToken);
    try {
        $query->execute();
       
        $message = 'Hola. Entra a http://localhost:8000/?page=verification&verification_token=' . $verificationToken . ' per a verificar el teu compte.';
      
        sendMail($message, $parameters['user_name'], $parameters['user_mail']);

        $configuration['{FEEDBACK}'] = 'Hem enviat un correu electrònic per a verificar el compte.<br> Cal verificar el compte abans de poder iniciar sessió <b>' . htmlentities($parameters['user_name']) . '</b>';
        //$configuration['{LOGIN_LOGOUT_TEXT}'] = 'Tancar sessió';
    } catch (Exception $e) {
        echo $e;
        $configuration['{FEEDBACK}'] = "<mark>ERROR: No s'ha pogut crear el compte <b>"
            . htmlentities($parameters['user_name']) . '</b></mark>';
    }
} else if (isset($parameters['login'])) {
    $db = new PDO($db_connection);
    $sql = 'SELECT * FROM users WHERE user_name = :user_name and user_password = :user_password and verified = 1';
    $query = $db->prepare($sql);
    $query->bindValue(':user_name', $parameters['user_name']);
    $query->bindValue(':user_password', hash_pbkdf2('sha512', $parameters['user_password'], $parameters['user_name'], 1000, 254, false) );
    $query->execute();
    $result_row = $query->fetchObject();
    if ($result_row) {
        $configuration['{FEEDBACK}'] = '"Sessió" iniciada com <b>' . htmlentities($parameters['user_name']) . '</b>';
        $configuration['{LOGIN_LOGOUT_TEXT}'] = 'Tancar "sessió"';
        $configuration['{LOGIN_LOGOUT_URL}'] = '/?page=logout';
        $session_token = random_int (PHP_INT_MIN, PHP_INT_MAX);
        $sql_token = 'UPDATE users SET session_token = :session_token WHERE user_name = :user_name';
        $query_token = $db->prepare ($sql_token);
        $query_token->bindValue(':session_token', $session_token);
        $query_token->bindValue(':user_name', $parameters['user_name']);
        $query_token->execute();
        setcookie ('session_user', $parameters['user_name']);
        setcookie ('session_token', $session_token);
    } else {
        $configuration['{FEEDBACK}'] = '<mark>ERROR: Usuari desconegut, contrasenya incorrecta o usuari sense verificar</mark>';
    }
}else if (isset($parameters['reset_password'])){
    $db = new PDO($db_connection);
    $sql = 'UPDATE users SET user_password = :user_password, verification_token = null WHERE verification_token = :verification_token';
    $query = $db->prepare($sql);
    $query->bindValue(':user_password', hash_pbkdf2('sha512', $parameters['user_password'], $parameters['user_name'], 1000, 254, false) );
    $query->bindValue(':verification_token', $parameters['verification_token']);
    $query->execute();
    if ($query->rowCount() > 0) {
        $configuration['{FEEDBACK}'] = 'Contrasenya actualitzada. Ja pots iniciar sessió';
    } else {
        $configuration['{FEEDBACK}'] = '<mark>ERROR: El enllaç de validació ha expirat o l\'usuari ja ha sigut validat\'</mark>';
    } 
}else if (isset($parameters['send_recovery'])){
    $db = new PDO($db_connection);
    $sql = 'SELECT * FROM users WHERE user_name = :user_name';
    $query = $db->prepare($sql);
    $query->bindValue(':user_name', $parameters['user_name']);
    $query->execute();
    $result_row = $query->fetchObject();
    if ($result_row) {
        $db = new PDO($db_connection);
        $sql = 'UPDATE users SET verification_token = :verification_token WHERE user_name = :user_name';
        $query = $db->prepare($sql);
        $verificationToken = hash_pbkdf2('sha512', $parameters['user_name'], time(), 1000, 100, false);
        $query->bindValue(':verification_token', $verificationToken);
        $query->bindValue(':user_name', $parameters['user_name']);
        $query->execute();
        if ($query->rowCount() > 0) {     
            $message = 'Hola. Entra a http://localhost:8000/?page=reset_password&verification_token=' . $verificationToken . ' per a recuperar el teu password.';
            sendMail($message, $parameters['user_name'], $result_row->user_mail);
            $configuration['{FEEDBACK}'] = 'Hem enviat un correu electrònic per a recuperar la teva contrasenya.';
        } else {
            $configuration['{FEEDBACK}'] = '<mark>ERROR: No s\'ha pogut trobar l\'usuari</mark>';
        } 

    } else {
        $configuration['{FEEDBACK}'] = '<mark>ERROR: Usuari desconegut</mark>';
    }
} else if (isset ($_COOKIE['session_token'])) {
    $db = new PDO($db_connection);
    $sql = 'SELECT * FROM users WHERE user_name = :user_name and session_token = :session_token';
    $query = $db->prepare($sql);
    $query->bindValue(':user_name', $_COOKIE['session_user']);
    $query->bindValue(':session_token', $_COOKIE['session_token']);
    $query->execute();
    $result_row = $query->fetchObject();
    if ($result_row) {
        $configuration['{FEEDBACK}'] = '"Sessió" iniciada com <b>' . htmlentities($_COOKIE['session_user']) . '</b>';
        $configuration['{LOGIN_LOGOUT_TEXT}'] = 'Tancar "sessió"';
        $configuration['{LOGIN_LOGOUT_URL}'] = '/?page=logout';
    }
}

// process template and show output
$html = file_get_contents('plantilla_' . $template . '.html', true);
$html = str_replace(array_keys($configuration), array_values($configuration), $html);
echo $html;

