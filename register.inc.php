<?php
declare(strict_types=1);

session_start();

require '../../assets/includes/auth_functions.php';
require '../../assets/includes/datacheck.php';
require '../../assets/includes/security_functions.php';

check_logged_out();

// Garante que é POST e que veio do formulário correto
if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_POST['signupsubmit'])) {
    header('Location: ../');
    exit();
}

/*
 * -------------------------------------------------------------------------------
 *   Securing against Header Injection
 * -------------------------------------------------------------------------------
 */
foreach ($_POST as $key => $value) {
    $_POST[$key] = _cleaninjections(trim((string)$value));
}

/*
 * -------------------------------------------------------------------------------
 *   Verifying CSRF token
 * -------------------------------------------------------------------------------
 */
if (!verify_csrf_token()) {
    $_SESSION['STATUS']['signupstatus'] = 'Request could not be validated';
    header('Location: ../');
    exit();
}

require '../../assets/setup/db.inc.php';

/*
 * -------------------------------------------------------------------------------
 *   Input filtering (sem escapar HTML aqui; escape na saída)
 * -------------------------------------------------------------------------------
 */
function input_filter(string $data): string
{
    return trim($data);
}

$username       = input_filter($_POST['username']        ?? '');
$email          = input_filter($_POST['email']           ?? '');
$password       = $_POST['password']                    ?? ''; // senha crua
$passwordRepeat = $_POST['confirmpassword']             ?? '';
$headline       = input_filter($_POST['headline']        ?? '');
$bio            = input_filter($_POST['bio']             ?? '');
$full_name      = input_filter($_POST['first_name']      ?? '');
$last_name      = input_filter($_POST['last_name']       ?? '');
$gender         = isset($_POST['gender']) ? input_filter($_POST['gender']) : null;

/*
 * -------------------------------------------------------------------------------
 *   Data Validation
 * -------------------------------------------------------------------------------
 */
if ($username === '' || $email === '' || $password === '' || $passwordRepeat === '') {
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

if (strlen($password) < 8) {
    $_SESSION['ERRORS']['passworderror'] = 'password must be at least 8 characters';
    header('Location: ../');
    exit();
}

// Verifica disponibilidade de username e email (funções devem usar prepared statements)
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

if (!empty($_FILES['avatar']['name'] ?? '')) {

    $file = $_FILES['avatar'];

    // Erro de upload
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $_SESSION['ERRORS']['imageerror'] = 'image upload failed, try again';
        header('Location: ../');
        exit();
    }

    // Tamanho máximo 10MB
    if ($file['size'] > 10 * 1024 * 1024) {
        $_SESSION['ERRORS']['imageerror'] = 'image size should be less than 10MB';
        header('Location: ../');
        exit();
    }

    $fileExt = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $allowedExt = ['jpg', 'jpeg', 'png', 'gif'];

    if (!in_array($fileExt, $allowedExt, true)) {
        $_SESSION['ERRORS']['imageerror'] = 'invalid image type, try again';
        header('Location: ../');
        exit();
    }

    // Verifica MIME real do arquivo
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime  = $finfo->file($file['tmp_name']);
    $allowedMime = ['image/jpeg', 'image/png', 'image/gif'];

    if (!in_array($mime, $allowedMime, true)) {
        $_SESSION['ERRORS']['imageerror'] = 'invalid image content, try again';
        header('Location: ../');
        exit();
    }

    if (!is_uploaded_file($file['tmp_name'])) {
        $_SESSION['ERRORS']['imageerror'] = 'possible file upload attack detected';
        header('Location: ../');
        exit();
    }

    // Gera nome aleatório seguro
    $FileNameNew = bin2hex(random_bytes(16)) . '.' . $fileExt;

    $uploadDir = realpath(__DIR__ . '/../../assets/uploads/users');
    if ($uploadDir === false || !is_dir($uploadDir) || !is_writable($uploadDir)) {
        $_SESSION['ERRORS']['imageerror'] = 'upload directory not available';
        header('Location: ../');
        exit();
    }

    $fileDestination = $uploadDir . DIRECTORY_SEPARATOR . $FileNameNew;

    if (!move_uploaded_file($file['tmp_name'], $fileDestination)) {
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
$sql = "
    INSERT INTO users (
        username, email, password, first_name, last_name, gender,
        headline, bio, profile_image, created_at
    ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW()
    )
";

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

if (!mysqli_stmt_execute($stmt)) {
    $_SESSION['ERRORS']['scripterror'] = 'Could not create user';
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

mysqli_stmt_close($stmt);
mysqli_close($conn);

header('Location: ../../login/');
exit();
