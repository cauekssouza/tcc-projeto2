<?php

session_start();

require '../../assets/includes/auth_functions.php';
require '../../assets/includes/datacheck.php';
require '../../assets/includes/security_functions.php';

check_logged_out();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['signupsubmit'])) {

    /*
    * -------------------------------------------------------------------------------
    *   Verificando CSRF ANTES de mexer em $_POST
    * -------------------------------------------------------------------------------
    */

    if (!verify_csrf_token()) {
        $_SESSION['STATUS']['signupstatus'] = 'Request could not be validated';
        header('Location: ../');
        exit();
    }

    /*
    * -------------------------------------------------------------------------------
    *   Securing against Header Injection (apenas campos de texto comuns)
    * -------------------------------------------------------------------------------
    */

    foreach ($_POST as $key => $value) {
        // Não altere campos sensíveis como o token de CSRF, se ele estiver em $_POST
        if ($key !== 'csrf_token') {
            $_POST[$key] = _cleaninjections(trim($value));
        }
    }

    require '../../assets/setup/db.inc.php';

    // Filtro de entrada mais cuidadoso
    function input_filter_string($data) {
        $data = trim($data);
        // Não usar stripslashes aqui; se magic_quotes estiver desativado, é desnecessário
        // Escapar HTML deve ser feito na saída, mas se quiser minimizar risco:
        return $data;
    }

    function input_filter_email($data) {
        return filter_var(trim($data), FILTER_SANITIZE_EMAIL);
    }

    // Senha: apenas trim, sem htmlspecialchars
    function input_filter_password($data) {
        return trim($data);
    }

    $username       = input_filter_string($_POST['username'] ?? '');
    $email          = input_filter_email($_POST['email'] ?? '');
    $password       = input_filter_password($_POST['password'] ?? '');
    $passwordRepeat = input_filter_password($_POST['confirmpassword'] ?? '');
    $headline       = input_filter_string($_POST['headline'] ?? '');
    $bio            = input_filter_string($_POST['bio'] ?? '');
    $full_name      = input_filter_string($_POST['first_name'] ?? '');
    $last_name      = input_filter_string($_POST['last_name'] ?? '');
    $gender         = isset($_POST['gender']) ? input_filter_string($_POST['gender']) : null;

    /*
    * -------------------------------------------------------------------------------
    *   Data Validation
    * -------------------------------------------------------------------------------
    */

    if (empty($username) || empty($email) || empty($password) || empty($passwordRepeat)) {
        $_SESSION['ERRORS']['formerror'] = 'required fields cannot be empty, try again';
        header('Location: ../');
        exit();
    }

    if (!preg_match('/^[a-zA-Z0-9_]{3,32}$/', $username)) {
        $_SESSION['ERRORS']['usernameerror'] = 'invalid username';
        header('Location: ../');
        exit();
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $_SESSION['ERRORS']['emailerror'] = 'invalid email';
        header('Location: ../');
        exit();
    }

    if ($password !== $passwordRepeat) {
        $_SESSION['ERRORS']['passworderror'] = 'passwords donot match';
        header('Location: ../');
        exit();
    }

    // Opcional: validar tamanho mínimo da senha
    if (strlen($password) < 8) {
        $_SESSION['ERRORS']['passworderror'] = 'password too short';
        header('Location: ../');
        exit();
    }

    // Validações de tamanho para campos de texto (evitar abuso)
    if (strlen($headline) > 255 || strlen($full_name) > 100 || strlen($last_name) > 100) {
        $_SESSION['ERRORS']['formerror'] = 'some fields are too long';
        header('Location: ../');
        exit();
    }

    // Verificar disponibilidade de username/email
    if (!availableUsername($conn, $username)) {
        $_SESSION['ERRORS']['usernameerror'] = 'username already taken';
        header('Location: ../');
        exit();
    }

    if (!availableEmail($conn, $email)) {
        $_SESSION['ERRORS']['emailerror'] = 'email already taken';
        header('Location: ../');
        exit();
    }

    /*
    * -------------------------------------------------------------------------------
    *   Image Upload
    * -------------------------------------------------------------------------------
    */

    $FileNameNew = '_defaultUser.png';

    if (isset($_FILES['avatar']) && !empty($_FILES['avatar']['name'])) {

        $fileName    = $_FILES['avatar']['name'];
        $fileTmpName = $_FILES['avatar']['tmp_name'];
        $fileSize    = $_FILES['avatar']['size'];
        $fileError   = $_FILES['avatar']['error'];

        // Verifica se é realmente um upload
        if (!is_uploaded_file($fileTmpName)) {
            $_SESSION['ERRORS']['imageerror'] = 'invalid upload';
            header('Location: ../');
            exit();
        }

        $fileExt = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
        $allowed = ['jpg', 'jpeg', 'png', 'gif'];

        if (!in_array($fileExt, $allowed, true)) {
            $_SESSION['ERRORS']['imageerror'] = 'invalid image type, try again';
            header('Location: ../');
            exit();
        }

        if ($fileError !== UPLOAD_ERR_OK) {
            $_SESSION['ERRORS']['imageerror'] = 'image upload failed, try again';
            header('Location: ../');
            exit();
        }

        if ($fileSize > 10 * 1024 * 1024) { // 10MB
            $_SESSION['ERRORS']['imageerror'] = 'image size should be less than 10MB';
            header('Location: ../');
            exit();
        }

        // Verificação de MIME real (se possível)
        $finfo    = new finfo(FILEINFO_MIME_TYPE);
        $mimeType = $finfo->file($fileTmpName);
        $allowedMime = [
            'image/jpeg',
            'image/png',
            'image/gif',
        ];

        if (!in_array($mimeType, $allowedMime, true)) {
            $_SESSION['ERRORS']['imageerror'] = 'invalid image content';
            header('Location: ../');
            exit();
        }

        // Nome de arquivo seguro
        $FileNameNew = bin2hex(random_bytes(16)) . '.' . $fileExt;
        $uploadDir   = realpath(__DIR__ . '/../../assets/uploads/users');

        if ($uploadDir === false) {
            $_SESSION['ERRORS']['imageerror'] = 'upload directory not found';
            header('Location: ../');
            exit();
        }

        $fileDestination = $uploadDir . DIRECTORY_SEPARATOR . $FileNameNew;

        if (!move_uploaded_file($fileTmpName, $fileDestination)) {
            $_SESSION['ERRORS']['imageerror'] = 'image upload failed, try again';
            header('Location: ../');
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
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW()
            )";

    $stmt = mysqli_stmt_init($conn);

    if (!mysqli_stmt_prepare($stmt, $sql)) {
        $_SESSION['ERRORS']['scripterror'] = 'SQL ERROR';
        header('Location: ../');
        exit();
    }

    $hashedPwd = password_hash($password, PASSWORD_DEFAULT);

    mysqli_stmt_bind_param(
        $stmt,
        'sssssssss',
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

    // Opcional: checar se realmente inseriu
    if (mysqli_stmt_affected_rows($stmt) !== 1) {
        $_SESSION['ERRORS']['scripterror'] = 'could not create user';
        header('Location: ../');
        exit();
    }

    /*
    * -------------------------------------------------------------------------------
    *   Sending Verification Email for Account Activation
    * -------------------------------------------------------------------------------
    */

    require 'sendverificationemail.inc.php';

    $_SESSION['STATUS']['loginstatus'] = 'Account Created, please Login';
    header('Location: ../../login/');
    exit();

    mysqli_stmt_close($stmt);
    mysqli_close($conn);

} else {
    header('Location: ../');
    exit();
}
