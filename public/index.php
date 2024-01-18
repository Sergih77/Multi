<?php

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

require 'vendor/autoload.php';

function randomPassword() {
    $alphabet = "abcdefghijklmnopqrstuwxyzABCDEFGHIJKLMNOPQRSTUWXYZ0123456789";
    $pass = array(); //remember to declare $pass as an array
    $alphaLength = strlen($alphabet) - 1; //put the length -1 in cache
    for ($i = 0; $i < 8; $i++) {
        $n = rand(0, $alphaLength);
        $pass[] = $alphabet[$n];
    }
    return implode($pass); //turn the array into a string
}

function RandomizeKeyboard() 
{   
    $keyboard = array("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z");
    $keyC = $keyboard[array_rand($keyboard,1)];
    return $keyC;
}

// defaults
$template = 'home';
$db_connection = 'sqlite:..\private\users.db';
$configuration = array(
    '{FEEDBACK}'          => '',
    '{LOGIN_LOGOUT_TEXT}' => 'Identificar-me',
    '{LOGIN_LOGOUT_URL}'  => '/login',
    '{METHOD}'            => 'POST', 
    '{REGISTER_URL}'      => '/register',
    '{SITE_NAME}'         => 'La meva pàgina',
    '{MailReset_URL}'      => '/mail_reset',
    '{CHANGEPASSWORD_URL}' => '/change_password',
    '{CHANGEPASSWORD_TEXT}' => '',
);

$parameters = array_merge($_GET, $_POST);

if (array_key_exists('page', $parameters) && $parameters['page'] == 'game'){
    // Tornem la plantilla del joc
    $html = file_get_contents('plantilla_game.html', true);
    $html = str_replace(array_keys($configuration), array_values($configuration), $html);
    echo("aaaaaaaaaaaaaaaaaaaaaaaa");
    echo $html;
}
//problema &post, crar pagina nueva
else {
    if (isset($_POST['page'])) {
        if ($_POST['page'] == 'Registrar-me') {
            $template = 'register';
            $configuration['{REGISTER_USERNAME}'] = '';
            $configuration['{LOGIN_LOGOUT_TEXT}'] = 'Ja tinc un compte';
            $html = file_get_contents('plantilla_' . $template . '.html', true);
            $html = str_replace(array_keys($configuration), array_values($configuration), $html);
            echo $html;
        } else if ($_POST['page'] == 'Identificar-me') {
            if (isset($_COOKIE['COOKIE1'])){
                $configuration['{FEEDBACK}'] = '"Sessió" iniciada com <b>' . htmlentities($_COOKIE['COOKIE1']) . '</b>';
                //$configuration['{LOGIN_LOGOUT_URL}'] = '/?page=game';
                $template = 'inici_game';
            }
            else{
                $template = 'login';
                $configuration['{LOGIN_USERNAME}'] = '';
            }
            $html = file_get_contents('plantilla_' . $template . '.html', true);
            $html = str_replace(array_keys($configuration), array_values($configuration), $html);
            echo $html;
        }
        else if($_POST['page'] == 'Tancar sessió'){
                setcookie('COOKIE1', $_COOKIE['COOKIE1'], time());
                $html = file_get_contents('plantilla_' . $template . '.html', true);
                $html = str_replace(array_keys($configuration), array_values($configuration), $html);
                echo $html;
        }   
        else if ($_POST['page'] == 'Enviar Correu') {
            $template = 'ResetMail';
            $configuration['{LOGIN_USERNAME}'] = '';
            $html = file_get_contents('plantilla_' . $template . '.html', true);
            $html = str_replace(array_keys($configuration), array_values($configuration), $html);
            echo $html;
        }else if ($_POST['page'] == 'Canviar contrasenya') {
            $template = 'ChangePassword';
            $configuration['{LOGIN_USERNAME}'] = '';
            $html = file_get_contents('plantilla_' . $template . '.html', true);
            $html = str_replace(array_keys($configuration), array_values($configuration), $html);
            echo $html;
        }

        if ($_POST['page'] == 'Crear compte') {


            $aux=sha1($parameters['user_password']);

            $result = substr($aux, 0, 5);

            $findme = substr($aux, 5, strlen($aux));

            //$myString = strpos($response, $findme);

            $html = file_get_contents('https://api.pwnedpasswords.com/range/' . $result . '');

            echo gettype($html);
            echo gettype($findme);
            echo "<br>";
            echo $aux;
            echo "<br>";
            echo $findme;

            if (stripos($html, $findme) !== false){
                echo("         ta mmal");
            }
            else{
                echo("          ta bien");
            }


            $db = new PDO($db_connection);
            $sql = 'INSERT INTO users (user_name,user_numero, user_email, user_hash) VALUES (:user_name, :user_numero, :user_email, :user_hash)';
            $query = $db->prepare($sql);
            $query->bindValue(':user_name',$_POST['user_name']);
            $query->bindValue(':user_numero', $_POST['user_numero']);
            $query->bindValue(':user_email', $_POST['user_email']);
            $options = [
                'cost' => 12,
            ];
            $hash=password_hash($_POST['user_password'], PASSWORD_BCRYPT, $options);
            $query->bindValue(':user_hash', $hash);
            $query->execute();
            if (strlen($_POST['user_password']) >= 8){
                    $configuration['{FEEDBACK}'] = 'Creat el compte <b>' . htmlentities($_POST['user_name']) . '</b>';
                    $configuration['{LOGIN_LOGOUT_TEXT}'] = 'Tancar sessió';
                    $configuration['{CHANGEPASSWORD_TEXT}'] = 'Canvia la meva contrasenya';
                    $template = 'inici_game';
                    if (isset($_COOKIE['COOKIE1'])){
                        setcookie('COOKIE1', $_COOKIE['COOKIE1'], time());
                        setcookie('COOKIE1', $_POST['user_name']);
                    }
                    else{
                        setcookie('COOKIE1', $_POST['user_name']);
                    }  
                
            } else {
                // Això no s'executarà mai (???)
                $configuration['{FEEDBACK}'] = "<mark>ERROR: La contrasenya ha de tenir mínim 8 caràcters <b>"
                    . htmlentities($_POST['user_name']) . '</b></mark>';
                $template = 'error';
            }
            $html = file_get_contents('plantilla_' . $template . '.html', true);
            $html = str_replace(array_keys($configuration), array_values($configuration), $html);
            echo $html;
        }else if ($_POST['page'] == 'Iniciar sessió') {
                $db = new PDO($db_connection);
                $sql='SELECT * FROM users WHERE user_name = :user_name';
                $query = $db->prepare($sql);
                $query->bindValue(':user_name', $_POST['user_name']);
                $query->execute();
                $result_row = $query->fetchObject();
                //if (password_verify($result_row->user_password, $result_row->user_hash)) {

                if($result_row){
                    if(password_verify($_POST['user_password'], $result_row->user_hash)){
                        setcookie('COOKIE1', $_POST['user_name']);
                        $configuration['{FEEDBACK}'] = '"Sessió" iniciada com <b>' . htmlentities($_POST['user_name']) . '</b>';
                        $configuration['{LOGIN_LOGOUT_URL}'] = '/logout';
                        $configuration['{CHANGEPASSWORD_TEXT}'] = 'Canvia la meva contrasenya';
                        $template = 'inici_game';
                    } 
                }else {
                    $configuration['{FEEDBACK}'] = '<mark>ERROR: Usuari desconegut o contrasenya incorrecta</mark>';
                    $template = 'error';
                }
                $html = file_get_contents('plantilla_' . $template . '.html', true);
                $html = str_replace(array_keys($configuration), array_values($configuration), $html);
                echo $html;
                
        }else if ($_POST['page'] == 'Enviar Correu') {
                $db = new PDO($db_connection);
                $sql = 'SELECT * FROM users WHERE user_email = :user_email';
                $query = $db->prepare($sql);
                $query->bindValue(':user_email', $_POST['user_email']);
                $query->execute();
                $result_row = $query->fetchObject();
                
                if ($result_row) {
                
                    $options = [
                        'cost' => 12,
                    ];
                
                    $Email=$_POST['user_email'];
                    $password = randomPassword();
                
                    $hash2=password_hash($password, PASSWORD_BCRYPT, $options);
                    $sql3 = "UPDATE users SET user_hash = '$hash2' WHERE user_email = '$Email';";
                    $query3 = $db->prepare($sql3);
                    #$query2->bindValue(':user_password', $password);
                    $query3->execute();
                    $result_row = $query3->fetchObject();
                    $mail = new PHPMailer();
                    $mail->isSMTP();
                    $mail->Host = 'smtp.gmail.com';
                    $mail->SMTPAuth = true;
                    $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
                    $mail->Port = 587;
                    $mail->SMTPSecure = "tls";
                    $mail->Username = 'P1MailSisMulti@gmail.com';
                    $mail->Password = 'rwvnzlibbogdoqfn';
                    $mail->setFrom('P1MailSisMulti@gmail.com', 'P1');
                    $mail->addAddress($_POST['user_email']);
                    $mail->Subject = 'Mail recuperacio de contrasenya';
                    $mail->isHTML(true);
                    $mailContent = "<h1>Nova contrasenya</h1>
                    <p>S'ha canviat la teva contrasenya, ara es: $password</p>";
                    $mail->Body = $mailContent;
                    $template = 'home';
                    if($mail->send()){
                        echo 'Mail enviat';
                    }else{
                        echo 'Error al enviar el mail';
                        echo 'Mailer Error: ' . $mail->ErrorInfo;
                    }
                    $mail->smtpClose();
                } else {
                    echo 'No existeix el mail';
                }
            $html = file_get_contents('plantilla_' . $template . '.html', true);
            $html = str_replace(array_keys($configuration), array_values($configuration), $html);
            echo $html;
        }else if ($_POST['page'] == 'contrasenya') {
            $db = new PDO($db_connection);
            $sql = 'SELECT * FROM users WHERE user_name = :user_name';
            $query = $db->prepare($sql);
            $query->bindValue(':user_name', $_COOKIE['COOKIE1']);
            $query->execute();
            $result_row = $query->fetchObject();

            if ($result_row) {
                $options = [
                    'cost' => 12,
                ];
                $aux = $_POST['user_new_password'];
                if (strlen($aux) >= 8){
                    $aux2 = $result_row->user_name;
                    $template = 'inside';
                    $hash2=password_hash($aux, PASSWORD_BCRYPT, $options);
                    $sql3 = "UPDATE users SET user_hash = '$hash2' WHERE user_name = '$aux2';";
                    $query3 = $db->prepare($sql3);
                    #$query2->bindValue(':user_password', $password);
                    $query3->execute();
                    $result_row2 = $query3->fetchObject();
                        
                }else {
                    $configuration['{FEEDBACK}'] = '<mark>ERROR: contrasenya massa curta, minim 8 caracters</mark>';
                    $template = 'error';
                }
                    

            }else {
                echo "Contrasenya incorrecte";
            }
            $html = file_get_contents('plantilla_' . $template . '.html', true);
            $html = str_replace(array_keys($configuration), array_values($configuration), $html);
            echo $html;
        }else if ($_POST['page'] == 'Canviar Contrasenya') {
            $template = 'ChangePassword';
            $html = file_get_contents('plantilla_' . $template . '.html', true);
            $html = str_replace(array_keys($configuration), array_values($configuration), $html);
            echo $html;
        }
        //game
        else if($_POST['page'] == 'Iniciar joc'){
            if (!isset ($_COOKIE['session_token'])) {
                setcookie ('session_token', mt_rand(0,99999999));
            }// Tenim cookie, codi del joc
            
            $db = new PDO($db_connection);
            $sql = 'SELECT * FROM partides WHERE (player1 = :session_token OR player2 = :session_token) AND winner = 0';
            $query = $db->prepare($sql);
            $query->bindValue(':session_token', $_COOKIE['session_token']);
            $query->execute();
            $result_row = $query->fetchObject();
            if ($result_row) {
                // el jugador te una partida
                if ($result_row->player2 != NULL){
                    //echo $result_row->clau;
                    $request_body = file_get_contents('php://input');
                    $data = json_decode($request_body);
                    if ($data->letter == $result_row->clau){
                        $sql = '';
                        $aux = "";
                        if ($result_row->player1 == $_COOKIE['session_token']){
                            $aux = $result_row->puntuacio1;
                            $aux = $aux + 1;
                            if($aux>2){
                                $sql = "UPDATE partides SET winner = 1 WHERE id = :id ;";
                                $query = $db->prepare($sql);
                                $query->bindValue(':id', $result_row->id);
                                $query->execute();
                                $sql = "UPDATE partides SET puntuacio1 = '$aux' WHERE id = :id ;";
                            }else{
                                $sql = "UPDATE partides SET puntuacio1 = '$aux' WHERE id = :id ;";
                                //$sql = 'UPDATE partides SET winner = 1 WHERE id = :id';
                            }
                        }else{
                            $aux = $result_row->puntuacio2;
                            $aux = $aux + 1;
                            if($aux>2){
                                $sql = "UPDATE partides SET winner = 2 WHERE id = :id ;";
                                $query = $db->prepare($sql);
                                $query->bindValue(':id', $result_row->id);
                                $query->execute();
                                $sql = "UPDATE partides SET puntuacio2 = '$aux' WHERE id = :id ;";
                            }else{
                                $sql = "UPDATE partides SET puntuacio2 = '$aux' WHERE id = :id ;";
                            }
                        }
                             
                        $query = $db->prepare($sql);
                        $query->bindValue(':id', $result_row->id);
                        //$query->bindValue(':puntuacio1', $result_row->puntuacio1);
                        $query->execute();
                    }
            
            
                    if ($data->letter != NULL){
                        $actual_letter = RandomizeKeyboard();
                        $sql = "UPDATE partides SET clau = '$actual_letter' WHERE id = :id AND winner = 0;";
                        $query = $db->prepare($sql);
                        $query->bindValue(':id', $result_row->id);
                        $query->execute();
                    }
            
                    $ping=$data->temps;
                    if ($ping!=NULL){
                        if ($result_row->player1 == $_COOKIE['session_token']){
                            $sql = "UPDATE partides SET ping1 = '$ping' WHERE id = :id AND winner = 0;";
                            $query = $db->prepare($sql);
                            $query->bindValue(':id', $result_row->id);
                            $query->execute();
                        }else{
                            $sql = "UPDATE partides SET ping2 = '$ping' WHERE id = :id AND winner = 0;";
                            $query = $db->prepare($sql);
                            $query->bindValue(':id', $result_row->id);
                            $query->execute();
                        }
                    }
            
                    $sql = 'SELECT * FROM partides WHERE id = :id ';
                    $query = $db->prepare($sql);
                    $query->bindValue(':id', $result_row->id);
                    $query->execute();
                    $result_row = $query->fetchObject();
            
                    $estatDeLaPartida = [
                        "player1" => $result_row->player1,
                        "player2" => $result_row->player2,
                        "winner" => $result_row->winner,
                        "puntuacio1" => $result_row->puntuacio1,
                        "puntuacio2" => $result_row->puntuacio2,
                        "clau" => $result_row->clau,
                        "ping1" => $result_row->ping1,
                        "ping2" => $result_row->ping2
                    ];
                        
                    echo json_encode($estatDeLaPartida);
                }else{
                    echo "No hi ha jugador 2";
                }
            } else {
                // el jugador NO te partida
                // Busquem si hi ha una partida amb espai
                $db = new PDO($db_connection);
                $sql = 'SELECT * FROM partides WHERE player2 IS NULL limit 1';
                $query = $db->prepare($sql);
                $query->execute();
                $result_row = $query->fetchObject();
                if ($result_row) {
                    // Hem trobat una partida, li assignem el usuari com a jugador 2
                    try {
                        //echo "BBBB";
                        $sql = 'UPDATE partides SET player2 = :session_token WHERE id = :id';
                        $query = $db->prepare($sql);
                        $query->bindValue(':session_token', $_COOKIE['session_token']);
                        $query->bindValue(':id', $result_row->id);
                        $query->execute();
                        } catch (Exception $e) {
                            echo $e;
                        }  
                } else {
                    // no trobem partida, en creem una
                    try {
                        //echo "AAAA";
                        $rn = RandomizeKeyboard();
                        $sql = "INSERT INTO partides (id, player1, player2, winner, puntuacio1, puntuacio2, clau, ping1, ping2) VALUES (null, :session_token, null, 0, 0, 0, '$rn', 0, 0);";
                        $query = $db->prepare($sql);
                        $query->bindValue(':session_token', $_COOKIE['session_token']);
                        $query->execute();
            
                        } catch (Exception $e) {
                            echo $e;
                        }  
                } 
            }
        }

    }
    else{
        $html = file_get_contents('plantilla_' . $template . '.html', true);
        $html = str_replace(array_keys($configuration), array_values($configuration), $html);
        echo $html;
    }
}
