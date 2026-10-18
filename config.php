<?php
// config.php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// PENGATURAN DATABASE
// Kalau di AWebServer, pakai 'root' dan password kosong.
// Kalau di hosting (cPanel), ubah sesuai data dari hostingmu.
$host = '127.0.0.1';
$db   = 'vexalithra';
$user = 'root'; 
$pass = 'root'; 

$dsn = "mysql:host=$host;dbname=$db;charset=utf8mb4";
$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (\PDOException $e) {
    die("Koneksi Database Gagal. Pastikan config.php sudah benar. Error: " . $e->getMessage());
}

// Fungsi Bantuan Umum
function redirect($url) { header("Location: $url"); exit; }
function is_login() { return isset($_SESSION['user_id']); }
function is_admin() { return is_login() && in_array($_SESSION['role'], ['admin', 'lead']); }
function is_pentester() { return is_login() && in_array($_SESSION['role'], ['admin', 'lead', 'pentester']); }
function h($str) { return htmlspecialchars($str ?? '', ENT_QUOTES, 'UTF-8'); }