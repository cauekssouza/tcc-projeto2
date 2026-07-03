<?php

session_start();

require '../../assets/includes/auth_functions.php';
require '../../assets/includes/datacheck.php';
require '../../assets/includes/security_functions.php';

check_logged_out();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['signupsubmit'])) {

    /*
    * -------------------------------------------------------------------------------
    *   Securing against Header Injection
    * -------------------------------------------------------------------------------
    */
    foreach ($_POST as $key => $value) {
        // Mantém limpeza contra header injection, mas sem quebrar dados sensíveis
        $_POST[$key] = _cleaninjections(trim($value));
    }

    /*
    * -------------------------------------------------------------------------------
    *   Verifying CSRF token
    * -------------------------------------------------------------------------------
    */
    if (!verify_csrf_token()) {
        $_SESSION['STATUS']['signupstatus'] = 'Request could not be validated';
        header("Location: ../");
        exit();
    }

    require '../../assets/setup/db.inc.php';

    // Filtro genérico para campos de texto (NÃO usar em senha)
    function input_filter($data) {
        $data = trim($data);
        // Evita stripslashes (pode remover caracteres válidos)
        // $data = stripslashes($data);
        // htmlspecialchars é para saída, não para armazenamento em DB
        return $data;
    }

    // Coleta e filtra entradas
    $username       = input_filter($_POST['username'] ?? '');
    $email          = input_filter($_POST['email'] ?? '');
    $password       = $_POST['password'] ?? '';          // senha sem htmlspecialchars
    $passwordRepeat = $_POST['confirmpassword'] ?? '';
    $headline       = input_filter($_POST['headline'] ?? '');
    $bio            = input_filter($_POST['bio'] ?? '');
    $full_name      = input_filter($_POST['first_name'] ?? '');
    $last_name      = input_filter($_POST['last_name'] ?? '');

    $gender = isset($_POST['gender']) ? input_filter($_POST['gender']) : null;

    /*
    * -------------------------------------------------------------------------------
    *   Data Validation
    * -------------------------------------------------------------------------------
    */
    if (empty($username) || empty($email) || empty($password) || empty($passwordRepeat)) {
        $_SESSION['ERRORS']['formerror'] = 'required fields cannot be empty, try again';
        header("Location: ../");
        exit();
    }

    // Limite de tamanho para username (protege DB e UI)
    if (strlen($username) < 3 || strlen($username) > 32) {
        $_SESSION['ERRORS']['usernameerror'] = 'username length invalid';
        header("Location: ../");
        exit();
    }

    if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
        $_SESSION['ERRORS']['usernameerror'] = 'invalid username';
        header("Location: ../");
        exit();
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $_SESSION['ERRORS']['emailerror'] = 'invalid email';
        header("Location: ../");
        exit();
    }

    // Política mínima de senha (exemplo simples)
    if (strlen($password) < 8) {
        $_SESSION['ERRORS']['passworderror'] = 'password too short';
        header("Location: ../");
        exit();
    }

    if ($password !== $passwordRepeat) {
        $_SESSION['ERRORS']['passworderror'] = 'passwords donot match';
        header("Location: ../");
        exit();
    }

    // Verifica disponibilidade de username/email com funções seguras (prepared statements)
    if (!availableUsername($conn, $username)) {
        $_SESSION['ERRORS']['usernameerror'] = 'username already taken';
        header("Location: ../");
        exit();
    }

    if (!availableEmail($conn, $email)) {
        $_SESSION['ERRORS']['emailerror'] = 'email already taken';
        header("Location: ../");
        exit();
    }

    /*
    * -------------------------------------------------------------------------------
    *   Image Upload (hardening)
    * -------------------------------------------------------------------------------
    */
    $FileNameNew = '_defaultUser.png';

    if (isset($_FILES['avatar']) && !empty($_FILES['avatar']['name'])) {

        $fileName    = $_FILES['avatar']['name'];
        $fileTmpName = $_FILES['avatar']['tmp_name'];
        $fileSize    = $_FILES['avatar']['size'];
        $fileError   = $_FILES['avatar']['error'];

        // Evita confiar em $_FILES['type']
        $fileExt = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
        $allowed = ['jpg', 'jpeg', 'png', 'gif'];

        if (!in_array($fileExt, $allowed, true)) {
            $_SESSION['ERRORS']['imageerror'] = 'invalid image type, try again';
            header("Location: ../");
            exit();
        }

        if ($fileError !== UPLOAD_ERR_OK) {
            $_SESSION['ERRORS']['imageerror'] = 'image upload failed, try again';
            header("Location: ../");
            exit();
        }

        if ($fileSize > 10 * 1024 * 1024) { // 10MB
            $_SESSION['ERRORS']['imageerror'] = 'image size should be less than 10MB';
            header("Location: ../");
            exit();
        }

        // Verifica MIME real do arquivo
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime  = $finfo->file($fileTmpName);
        $allowedMimes = [
            'image/jpeg',
            'image/png',
            'image/gif'
        ];

        if (!in_array($mime, $allowedMimes, true)) {
            $_SESSION['ERRORS']['imageerror'] = 'invalid image content, try again';
            header("Location: ../");
            exit();
        }

        // Gera nome seguro
        $FileNameNew = bin2hex(random_bytes(16)) . '.' . $fileExt;
        $uploadDir   = realpath('../../assets/uploads/users');

        if ($uploadDir === false) {
            $_SESSION['ERRORS']['imageerror'] = 'upload directory not found';
            header("Location: ../");
            exit();
        }

        $fileDestination = $uploadDir . DIRECTORY_SEPARATOR . $FileNameNew;

        if (!move_uploaded_file($fileTmpName, $fileDestination)) {
            $_SESSION['ERRORS']['imageerror'] = 'image upload failed, try again';
            header("Location: ../");
            exit();
        }
    }

    /*
    * -------------------------------------------------------------------------------
    *   User Creation
    * -------------------------------------------------------------------------------
    */
    $sql = "INSERT INTO users (
                username, email, password, first_name, last_name, gender,
                headline, bio, profile_image, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())";

    $stmt = mysqli_stmt_init($conn);

    if (!mysqli_stmt_prepare($stmt, $sql)) {
        $_SESSION['ERRORS']['scripterror'] = 'SQL ERROR';
        header("Location: ../");
        exit();
    }

    $hashedPwd = password_hash($password, PASSWORD_DEFAULT);

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
        $FileNameNew
    );

    mysqli_stmt_execute($stmt);

    // Opcional: verificar se inserção realmente ocorreu
    if (mysqli_stmt_affected_rows($stmt) !== 1) {
        $_SESSION['ERRORS']['scripterror'] = 'Account could not be created';
        header("Location: ../");
        exit();
    }

    /*
    * -------------------------------------------------------------------------------
    *   Sending Verification Email for Account Activation
    * -------------------------------------------------------------------------------
    */
    require 'sendverificationemail.inc.php';

    $_SESSION['STATUS']['loginstatus'] = 'Account Created, please Login';
    header("Location: ../../login/");
    exit();

    mysqli_stmt_close($stmt);
    mysqli_close($conn);

} else {
    header("Location: ../");
    exit();
}
