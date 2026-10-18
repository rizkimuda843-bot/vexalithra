<?php
require 'config.php';

function scan_target($url) {
    $findings = [];
    
    // Daftar file sensitif yang akan dites
    $sensitive_files = [
        '/.env', 
        '/.git/config', 
        '/config.php.bak', 
        '/phpinfo.php', 
        '/backup.sql', 
        '/.DS_Store'
    ];

    // Setup cURL
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 8);
    curl_setopt($ch, CURLOPT_USERAGENT, 'VEXALITHRA-Scanner/1.0');

    foreach ($sensitive_files as $path) {
        $target_url = rtrim($url, '/') . $path;
        curl_setopt($ch, CURLOPT_URL, $target_url);
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        if ($http_code == 200 && !empty($response)) {
            // FILTER ANTI-NGASAL:
            // 1. Cek apakah ini halaman HTML biasa
            $is_html = preg_match('/<html|<body|<!DOCTYPE/i', $response);
            
            // 2. Cek apakah ada indikator file bocor
            $has_indicator = preg_match('/(DB_|PASSWORD|SECRET|<\?php|root:x:0:0|\[core\]|extension=)/i', $response);
            
            // Jika BUKAN html biasa DAN punya indikator bocor, baru simpan
            if (!$is_html && $has_indicator) {
                // Ambil maksimal 5000 karakter pertama agar database tidak penuh
                $raw_code = substr($response, 0, 5000); 
                
                $findings[] = [
                    'title' => "File Bocor: " . $path,
                    'severity' => 'high',
                    'category' => 'Exposed File',
                    'description' => "File $path dapat diakses publik. Source code berhasil diambil.",
                    'raw_code' => $raw_code
                ];
            }
        }
    }
    curl_close($ch);
    return $findings;
}
?>