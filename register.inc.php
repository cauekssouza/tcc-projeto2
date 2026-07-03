<?php
declare(strict_types=1);

session_start();

require '../../assets/includes/auth_functions.php';
require '../../assets/includes/datacheck.php';
require '../../assets/includes/security_functions.php';

check_logged_out();

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
    // Garante string e remove possíveis injeções em cabeçalho
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
 *   Input filtering (sem mexer em senha)
 * -------------------------------------------------------------------------------
 */
function input_filter(string $data): string {
    $data = trim($data);
    // stripslashes raramente é necessário hoje, mas mantido por compatibilidade
    $data = stripslashes($data);
    // NÃO usar htmlspecialchars aqui para dados que vão para o banco;
    // escapar deve ser feito na saída (na view), não na entrada.
    return $data;
}

$username       = input_filter($_POST['username'] ?? '');
$email          = input_filter($_POST['email'] ?? '');
$password       = $_POST['password'] ?? '';          // senha crua, sem filtros
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

// Política mínima de senha (exemplo simples)
if (strlen($password) < 8) {
    $_SESSION['ERRORS']['passworderror'] = 'password must be at least 8 characters';
    header('Location: ../');
    exit();
}

// Verificações de disponibilidade (assumindo que usam prepared statements internamente)
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

if (isset($_FILES['avatar']) && is_array($_FILES['avatar']) && !empty($_FILES['avatar']['name'])) {
    $fileName    = $_FILES['avatar']['name'];
    $fileTmpName = $_FILES['avatar']['tmp_name'];
    $fileSize    = (int)$_FILES['avatar']['size'];
    $fileError   = (int)$_FILES['avatar']['error'];
    $fileType    = $_FILES['avatar']['type'];

    // Extensão
    $fileExt       = explode('.', $fileName);
    $fileActualExt = strtolower(end($fileExt));

    $allowedExt = ['jpg', 'jpeg', 'png', 'gif'];

    if (!in_array($fileActualExt, $allowedExt, true)) {
        $_SESSION['ERRORS']['imageerror'] = 'invalid image type, try again';
        header('Location: ../');
        exit();
    }

    if ($fileError !== UPLOAD_ERR_OK) {
        $_SESSION['ERRORS']['imageerror'] = 'image upload failed, try again';
        header('Location: ../');
        exit();
    }

    // Limite de 10MB
    if ($fileSize > 10 * 1024 * 1024) {
        $_SESSION['ERRORS']['imageerror'] = 'image size should be less than 10MB';
        header('Location: ../');
        exit();
    }

    // Verificação de upload válido
    if (!is_uploaded_file($fileTmpName)) {
        $_SESSION['ERRORS']['imageerror'] = 'invalid upload, try again';
        header('Location: ../');
        exit();
    }

    // Verificação simples de MIME (não perfeito, mas melhor que nada)
    $finfo    = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = $finfo ? finfo_file($finfo, $fileTmpName) : null;
    if ($finfo) {
        finfo_close($finfo);
    }

    $allowedMime = ['image/jpeg', 'image/png', 'image/gif'];
    if ($mimeType === null || !in_array($mimeType, $allowedMime, true)) {
        $_SESSION['ERRORS']['imageerror'] = 'invalid image mime type, try again';
        header('Location: ../');
        exit();
    }

    // Gera nome seguro
    $FileNameNew     = bin2hex(random_bytes(16)) . '.' . $fileActualExt;
    $uploadDir       = realpath(__DIR__ . '/../../assets/uploads/users');
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
$sql = 'INSERT INTO users (
            username,
            email,
            password,
            first_name,
            last_name,
            gender,
            headline,
            bio,
            profile_image,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())';

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

// Não é necessário mysqli_stmt_store_result() para INSERT
mysqli_stmt_close($stmt);
mysqli_close($conn);

/*
 * -------------------------------------------------------------------------------
 *   Sending Verification Email for Account Activation
 * -------------------------------------------------------------------------------
 */
require 'sendverificationemail.inc.php';

$_SESSION['STATUS']['loginstatus'] = 'Account Created, please Login';
header('Location: ../../login/');
exit();
