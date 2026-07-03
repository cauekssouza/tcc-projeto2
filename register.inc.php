<?php
declare(strict_types=1);

session_start();

require '../../assets/includes/auth_functions.php';
require '../../assets/includes/datacheck.php';
require '../../assets/includes/security_functions.php';

check_logged_out();

// Garante que é POST
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
    // Mantém apenas strings, evita arrays maliciosos
    if (is_string($value)) {
        $_POST[$key] = _cleaninjections(trim($value));
    }
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

if (!isset($conn) || !$conn instanceof mysqli) {
    $_SESSION['ERRORS']['scripterror'] = 'Database connection error';
    header('Location: ../');
    exit();
}

/*
 * -------------------------------------------------------------------------------
 *   Input filter (sem mexer em senha)
 * -------------------------------------------------------------------------------
 */
function input_filter(string $data): string {
    $data = trim($data);
    // Evita remoção de barras que podem ser válidas
    // $data = stripslashes($data); // removido
    // Escapar para saída, não para armazenamento; aqui usamos apenas para sanitizar básico
    return $data;
}

$username       = input_filter($_POST['username'] ?? '');
$email          = input_filter($_POST['email'] ?? '');
$password       = $_POST['password'] ?? '';          // não aplicar htmlspecialchars
$passwordRepeat = $_POST['confirmpassword'] ?? '';
$headline       = input_filter($_POST['headline'] ?? '');
$bio            = input_filter($_POST['bio'] ?? '');
$full_name      = input_filter($_POST['first_name'] ?? '');
$last_name      = input_filter($_POST['last_name'] ?? '');
$gender         = isset($_POST['gender']) ? input_filter($_POST['gender']) : null;

/*
 * -------------------------------------------------------------------------------
 *   Data Validation
 * -------------------------------------------------------------------------------
 */

// Campos obrigatórios
if ($username === '' || $email === '' || $password === '' || $passwordRepeat === '') {
    $_SESSION['ERRORS']['formerror'] = 'required fields cannot be empty, try again';
    header('Location: ../');
    exit();
}

// Limites de tamanho básicos
if (strlen($username) > 50 || strlen($email) > 255 || strlen($headline) > 255 || strlen($bio) > 2000) {
    $_SESSION['ERRORS']['formerror'] = 'one or more fields are too long';
    header('Location: ../');
    exit();
}

// Username alfanumérico
if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
    $_SESSION['ERRORS']['usernameerror'] = 'invalid username';
    header('Location: ../');
    exit();
}

// Email válido
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $_SESSION['ERRORS']['emailerror'] = 'invalid email';
    header('Location: ../');
    exit();
}

// Senhas iguais
if (!hash_equals($password, $passwordRepeat)) {
    $_SESSION['ERRORS']['passworderror'] = 'passwords do not match';
    header('Location: ../');
    exit();
}

// Opcional: política mínima de senha
if (strlen($password) < 8) {
    $_SESSION['ERRORS']['passworderror'] = 'password must be at least 8 characters';
    header('Location: ../');
    exit();
}

/*
 * -------------------------------------------------------------------------------
 *   Check username/email availability
 * -------------------------------------------------------------------------------
 */
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
    $fileName    = $_FILES['avatar']['name'];
    $fileTmpName = $_FILES['avatar']['tmp_name'];
    $fileSize    = $_FILES['avatar']['size'];
    $fileError   = $_FILES['avatar']['error'];

    // Verifica se é upload válido
    if (!is_uploaded_file($fileTmpName)) {
        $_SESSION['ERRORS']['imageerror'] = 'invalid upload';
        header('Location: ../');
        exit();
    }

    // Extensão
    $fileExt      = explode('.', $fileName);
    $fileActualExt = strtolower(end($fileExt));
    $allowedExt    = ['jpg', 'jpeg', 'png', 'gif'];

    if (!in_array($fileActualExt, $allowedExt, true)) {
        $_SESSION['ERRORS']['imageerror'] = 'invalid image type, try again';
        header('Location: ../');
        exit();
    }

    // MIME real
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime  = $finfo->file($fileTmpName);
    $allowedMime = ['image/jpeg', 'image/png', 'image/gif'];

    if (!in_array($mime, $allowedMime, true)) {
        $_SESSION['ERRORS']['imageerror'] = 'invalid image mime type';
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

    // Nome seguro
    $FileNameNew = bin2hex(random_bytes(16)) . '.' . $fileActualExt;
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
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())";

$stmt = mysqli_stmt_init($conn);

if (!mysqli_stmt_prepare($stmt, $sql)) {
    $_SESSION['ERRORS']['scripterror'] = 'SQL ERROR';
    header('Location: ../');
    exit();
}

$hashedPwd = password_hash($password, PASSWORD_DEFAULT);
if ($hashedPwd === false) {
    $_SESSION['ERRORS']['scripterror'] = 'Password hashing failed';
    header('Location: ../');
    exit();
}

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
    $_SESSION['ERRORS']['scripterror'] = 'User creation failed';
    header('Location: ../');
    exit();
}

// Opcional: regenerar ID de sessão após criação de conta
session_regenerate_id(true);

/*
 * -------------------------------------------------------------------------------
 *   Sending Verification Email for Account Activation
 * -------------------------------------------------------------------------------
 */
require 'sendverificationemail.inc.php';

$_SESSION['STATUS']['loginstatus'] = 'Account Created, please Login';
header('Location: ../../login/');
exit();

// Fechamento
mysqli_stmt_close($stmt);
mysqli_close($conn);
