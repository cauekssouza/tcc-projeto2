<?php

session_start();

require '../../assets/includes/auth_functions.php';
require '../../assets/includes/datacheck.php';
require '../../assets/includes/security_functions.php';

check_logged_out();

if (isset($_POST['signupsubmit'])) {

    foreach($_POST as $key => $value){
        $_POST[$key] = _cleaninjections(trim($value));
    }

    if (!verify_csrf_token()){
        $_SESSION['STATUS']['signupstatus'] = 'Request could not be validated';
        header("Location: ../");
        exit();
    }

    require '../../assets/setup/db.inc.php';

    function input_filter($data) {
        return htmlspecialchars(stripslashes(trim($data)));
    }

    $username       = input_filter($_POST['username']);
    $email          = input_filter($_POST['email']);
    $password       = input_filter($_POST['password']);
    $passwordRepeat = input_filter($_POST['confirmpassword']);
    $headline       = input_filter($_POST['headline']);
    $bio            = input_filter($_POST['bio']);
    $full_name      = input_filter($_POST['first_name']);
    $last_name      = input_filter($_POST['last_name']);
    $gender         = isset($_POST['gender']) ? input_filter($_POST['gender']) : NULL;

    if (empty($username) || empty($email) || empty($password) || empty($passwordRepeat)) {
        $_SESSION['ERRORS']['formerror'] = 'required fields cannot be empty, try again';
        header("Location: ../");
        exit();
    }

    if (!preg_match("/^[a-zA-Z0-9]*$/", $username)) {
        $_SESSION['ERRORS']['usernameerror'] = 'invalid username';
        header("Location: ../");
        exit();
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $_SESSION['ERRORS']['emailerror'] = 'invalid email';
        header("Location: ../");
        exit();
    }

    if ($password !== $passwordRepeat) {
        $_SESSION['ERRORS']['passworderror'] = 'passwords donot match';
        header("Location: ../");
        exit();
    }

    if (!availableUsername($conn, $username)){
        $_SESSION['ERRORS']['usernameerror'] = 'username already taken';
        header("Location: ../");
        exit();
    }

    if (!availableEmail($conn, $email)){
        $_SESSION['ERRORS']['emailerror'] = 'email already taken';
        header("Location: ../");
        exit();
    }

    /*
    * -------------------------------------------------------------------------------
    *   Image Upload
    * -------------------------------------------------------------------------------
    */

    $FileNameNew = '_defaultUser.png';

    if (!empty($_FILES['avatar']['name'])){

        $fileName = $_FILES['avatar']['name'];
        $fileTmpName = $_FILES['avatar']['tmp_name'];
        $fileSize = $_FILES['avatar']['size'];
        $fileError = $_FILES['avatar']['error'];

        $fileExt = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
        $allowed = array('jpg', 'jpeg', 'png', 'gif');

        if (!in_array($fileExt, $allowed)) {
            $_SESSION['ERRORS']['imageerror'] = 'invalid image type, try again';
            header("Location: ../");
            exit();
        }

        if ($fileError !== 0) {
            $_SESSION['ERRORS']['imageerror'] = 'image upload failed, try again';
            header("Location: ../");
            exit();
        }

        if ($fileSize > 10000000) {
            $_SESSION['ERRORS']['imageerror'] = 'image size should be less than 10MB';
            header("Location: ../");
            exit();
        }

        $FileNameNew = bin2hex(random_bytes(16)) . "." . $fileExt;
        $fileDestination = '../../assets/uploads/users/' . $FileNameNew;
        move_uploaded_file($fileTmpName, $fileDestination);
    }

    /*
    * -------------------------------------------------------------------------------
    *   User Creation
    * -------------------------------------------------------------------------------
    */

    $sql = "INSERT INTO users(username, email, password, first_name, last_name, gender,
            headline, bio, profile_image, created_at, verification_token)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?)";

    $stmt = mysqli_stmt_init($conn);

    if (!mysqli_stmt_prepare($stmt, $sql)) {
        $_SESSION['ERRORS']['scripterror'] = 'SQL ERROR';
        header("Location: ../");
        exit();
    }

    /*
    * -------------------------------------------------------------------------------
    *   Secure password hashing (bcrypt/argon2)
    * -------------------------------------------------------------------------------
    */

    $hashedPwd = password_hash($password, PASSWORD_DEFAULT);

    /*
    * -------------------------------------------------------------------------------
    *   Secure HMAC token (OWASP recommended)
    * -------------------------------------------------------------------------------
    */

    $secretKey = getenv('APP_SECRET_KEY'); // coloque no .env
    if (!$secretKey) {
        $secretKey = bin2hex(random_bytes(32)); // fallback seguro
    }

    $verificationToken = hash_hmac(
        'sha256',
        $email . microtime(true),
        $secretKey
    );

    mysqli_stmt_bind_param(
        $stmt,
        "sssssssss",
        $username,
        $email,
        $hashedPwd,
        $full_name,
        $last_name,
        $gender,
        $headline,
        $bio,
        $FileNameNew,
        $verificationToken
    );

    mysqli_stmt_execute($stmt);
    mysqli_stmt_store_result($stmt);

    require 'sendverificationemail.inc.php';

    $_SESSION['STATUS']['loginstatus'] = 'Account Created, please Login';
    header("Location: ../../login/");
    exit();
}

header("Location: ../");
exit();
