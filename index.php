<?php
require 'config.php';
require 'scanner.php'; // Memanggil modul scanner

// ==========================================
// 1. PROSES LOGIN & LOGOUT
// ==========================================
if (isset($_POST['login'])) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$_POST['username']]);
    $user = $stmt->fetch();
    
    if ($user && password_verify($_POST['password'], $user['password'])) {
        $is_admin = in_array($user['role'], ['admin', 'lead']);
        if ($_POST['portal'] === 'admin' && !$is_admin) {
            $error = "Akses Ditolak. Anda bukan Admin.";
        } elseif ($_POST['portal'] === 'member' && $is_admin) {
            $error = "Akses Ditolak. Gunakan Portal Admin.";
        } else {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role'] = $user['role'];
            $_SESSION['display_name'] = $user['display_name'];
            redirect('index.php');
        }
    } else {
        $error = "Username atau Password salah!";
    }
}

if (isset($_GET['logout'])) {
    session_destroy();
    redirect('index.php');
}

// ==========================================
// 2. PROSES DATA (CRUD)
// ==========================================
// Tambah Anggota
if (isset($_POST['add_member']) && is_admin()) {
    try {
        $hashed_pw = password_hash($_POST['password'], PASSWORD_DEFAULT);
        $stmt = $pdo->prepare("INSERT INTO users (username, password, role, display_name) VALUES (?, ?, ?, ?)");
        $stmt->execute([trim($_POST['username']), $hashed_pw, $_POST['role'], trim($_POST['display_name'])]);
        $msg_member = "Anggota baru berhasil ditambahkan!";
    } catch (PDOException $e) { $error_member = "Gagal: Username mungkin sudah dipakai."; }
}

// Hapus Anggota
if (isset($_GET['delete_member']) && is_admin()) {
    $id = $_GET['delete_member'];
    if ($id != $_SESSION['user_id']) {
        $pdo->prepare("DELETE FROM users WHERE id = ?")->execute([$id]);
        $msg_member = "Anggota berhasil dihapus.";
    }
}

// Tambah Target
if (isset($_POST['add_target']) && is_admin()) {
    $stmt = $pdo->prepare("INSERT INTO targets (name, url, owner, permission_status) VALUES (?, ?, ?, ?)");
    $stmt->execute([trim($_POST['name']), trim($_POST['url']), trim($_POST['owner']), $_POST['permission_status']]);
    $msg_target = "Target berhasil ditambahkan!";
}

// Tambah Temuan Manual (Dengan Upload File)
if (isset($_POST['add_finding']) && is_pentester()) {
    $assigned = !empty($_POST['assigned_to']) ? $_POST['assigned_to'] : null;
    $evidence_path = null;

    if (isset($_FILES['evidence']) && $_FILES['evidence']['error'] == 0) {
        $allowed = ['jpg', 'jpeg', 'png', 'gif'];
        $ext = strtolower(pathinfo($_FILES['evidence']['name'], PATHINFO_EXTENSION));
        if (in_array($ext, $allowed)) {
            $newname = uniqid('img_') . '.' . $ext;
            move_uploaded_file($_FILES['evidence']['tmp_name'], 'uploads/' . $newname);
            $evidence_path = $newname;
        }
    }

    $stmt = $pdo->prepare("INSERT INTO findings (target_id, title, severity, category, description, assigned_to, found_by, evidence_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->execute([$_POST['target_id'], trim($_POST['title']), $_POST['severity'], trim($_POST['category']), trim($_POST['description']), $assigned, $_SESSION['user_id'], $evidence_path]);
    $msg_finding = "Temuan berhasil dicatat!";
}

// JALANKAN SCANNER OTOMATIS
if (isset($_POST['run_scan']) && is_pentester()) {
    $target_id = $_POST['scan_target_id'];
    $stmt = $pdo->prepare("SELECT * FROM targets WHERE id = ?");
    $stmt->execute([$target_id]);
    $t = $stmt->fetch();
    
    if ($t && $t['permission_status'] == 'granted') {
        $results = scan_target($t['url']);
        $count = 0;
        foreach ($results as $r) {
            $stmt = $pdo->prepare("INSERT INTO findings (target_id, title, severity, category, description, raw_code, assigned_to, found_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([$target_id, $r['title'], $r['severity'], $r['category'], $r['description'], $r['raw_code'], $_SESSION['user_id'], $_SESSION['user_id']]);
            $count++;
        }
        $msg_scan = ($count > 0) ? "Scan selesai! Ditemukan $count file bocor yang valid." : "Scan selesai. Tidak ada file bocor yang terdeteksi.";
    } else {
        $msg_scan = "Gagal: Target belum diizinkan (harus Granted).";
    }
}

// Ubah Status Temuan
if (isset($_POST['update_status']) && is_pentester()) {
    $stmt = $pdo->prepare("UPDATE findings SET status = ? WHERE id = ?");
    $stmt->execute([$_POST['status'], $_POST['finding_id']]);
    redirect('index.php?page=finding_detail&id=' . $_POST['finding_id']);
}

// ==========================================
// 3. AMBIL DATA
// ==========================================
$page = $_GET['page'] ?? 'home';
$members = $targets = $findings = [];

if (is_login()) {
    $members = $pdo->query("SELECT id, username, display_name FROM users")->fetchAll();
    $targets = $pdo->query("SELECT * FROM targets ORDER BY id DESC")->fetchAll();
    
    if (is_admin()) {
        $findings = $pdo->query("SELECT f.*, t.name as target_name FROM findings f JOIN targets t ON t.id = f.target_id ORDER BY f.id DESC")->fetchAll();
    } else {
        $stmt = $pdo->prepare("SELECT f.*, t.name as target_name FROM findings f JOIN targets t ON t.id = f.target_id WHERE f.assigned_to = ? ORDER BY f.id DESC");
        $stmt->execute([$_SESSION['user_id']]);
        $findings = $stmt->fetchAll();
    }
}

// ==========================================
// 4. LOGIKA CETAK LAPORAN & DETAIL
// ==========================================
if ($page === 'print_report' && is_admin() && isset($_GET['target_id'])) {
    $tid = $_GET['target_id'];
    $stmt = $pdo->prepare("SELECT * FROM targets WHERE id = ?"); $stmt->execute([$tid]); $t = $stmt->fetch();
    $stmt = $pdo->prepare("SELECT * FROM findings WHERE target_id = ? ORDER BY FIELD(severity, 'critical','high','medium','low')"); $stmt->execute([$tid]); $fs = $stmt->fetchAll();
    if (!$t) die("Target tidak ditemukan.");
    ?>
    <!DOCTYPE html><html lang="id"><head><meta charset="UTF-8"><title>Laporan - <?= h($t['name']) ?></title>
    <style>
        body { font-family: sans-serif; color: #333; padding: 20px; background: #fff; }
        .header { display: flex; align-items: center; border-bottom: 3px solid #000; padding-bottom: 15px; margin-bottom: 20px; }
        .header h1 { margin: 0; font-size: 24px; letter-spacing: 2px; } .header p { margin: 5px 0 0 0; color: #555; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 12px; } th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background: #f4f4f4; } .sev { font-weight: bold; text-transform: uppercase; }
        .btn { padding: 10px 20px; background: #000; color: #fff; border: none; cursor: pointer; margin-bottom: 20px; border-radius: 5px; }
        @media print { .btn { display: none; } body { padding: 0; } }
    </style></head><body>
    <button class="btn" onclick="window.print()">🖨️ Cetak / Simpan PDF</button>
    <div class="header">
        <svg viewBox="0 0 100 100" width="80" height="80"><path d="M50 5 L90 20 L90 50 C90 75 50 95 50 95 C50 95 10 75 10 50 L10 20 Z" fill="#0a0e14" stroke="#000" stroke-width="4"/><text x="50" y="60" font-family="monospace" font-size="30" font-weight="bold" fill="#fff" text-anchor="middle">VX</text></svg>
        <div><h1>VEXALITHRA</h1><p>Cybersecurity Research Team</p></div>
    </div>
    <h2>Laporan Hasil Pengujian Keamanan</h2>
    <p><b>Target:</b> <?= h($t['name']) ?> (<?= h($t['url']) ?>)<br><b>Pemilik:</b> <?= h($t['owner']) ?><br><b>Tanggal:</b> <?= date('d M Y') ?></p>
    <table><tr><th>No</th><th>Kerentanan</th><th>Severity</th><th>Status</th><th>Deskripsi</th></tr>
        <?php foreach($fs as $i => $f): ?><tr><td><?= $i+1 ?></td><td><b><?= h($f['title']) ?></b></td><td class="sev"><?= h($f['severity']) ?></td><td><?= h($f['status']) ?></td><td><?= nl2br(h($f['description'])) ?></td></tr><?php endforeach; ?>
    </table>
    </body></html>
    <?php exit;
}

if ($page === 'finding_detail' && is_login() && isset($_GET['id'])) {
    $stmt = $pdo->prepare("SELECT f.*, t.name as target_name FROM findings f JOIN targets t ON t.id = f.target_id WHERE f.id = ?");
    $stmt->execute([$_GET['id']]); $f = $stmt->fetch();
    if (!$f) die("Temuan tidak ditemukan.");
    if (!is_admin() && $f['assigned_to'] != $_SESSION['user_id']) die("Akses Ditolak.");
    
    $sev_colors = ['critical'=>'#f85149', 'high'=>'#d29922', 'medium'=>'#58a6ff', 'low'=>'#3fb950'];
    ?>
    <!DOCTYPE html><html lang="id"><head><meta charset="UTF-8"><title>Detail Temuan</title>
    <style>
        body { font-family: sans-serif; background: #0a0e14; color: #c9d1d9; padding: 20px; }
        .card { background: #161b22; border: 1px solid #30363d; padding: 20px; border-radius: 8px; max-width: 700px; margin: 0 auto; }
        h2 { color: #58a6ff; margin-top: 0; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; color: #000; }
        .img-evidence { max-width: 100%; border-radius: 5px; border: 1px solid #30363d; margin-top: 10px; }
        input, select { padding: 8px; background: #0d1117; color: white; border: 1px solid #30363d; border-radius: 5px; }
        button { padding: 8px 15px; background: #3fb950; color: #000; border: none; border-radius: 5px; font-weight: bold; cursor: pointer; }
        a { color: #58a6ff; text-decoration: none; display: inline-block; margin-bottom: 15px; }
    </style></head><body>
    <div class="card">
        <a href="index.php?page=findings">← Kembali ke Temuan</a>
        <h2><?= h($f['title']) ?></h2>
        <p><b>Target:</b> <?= h($f['target_name']) ?></p>
        <p><b>Severity:</b> <span class="badge" style="background:<?= $sev_colors[$f['severity']] ?>"><?= strtoupper($f['severity']) ?></span></p>
        <p><b>Status:</b> <?= strtoupper($f['status']) ?></p>
        <p><b>Deskripsi:</b><br><?= nl2br(h($f['description'])) ?></p>
        
        <?php if (!empty($f['raw_code'])): ?>
            <p><b>Source Code / Evidence (Dari Scanner):</b></p>
            <pre style="background:#000; color:#4af626; padding:15px; border-radius:6px; overflow-x:auto; font-family:monospace; font-size:12px; border:1px solid #30363d; white-space: pre-wrap; word-wrap: break-word;"><?= h($f['raw_code']) ?></pre>
        <?php endif; ?>

        <?php if ($f['evidence_path']): ?>
            <p><b>Bukti (Screenshot):</b></p>
            <img src="uploads/<?= h($f['evidence_path']) ?>" class="img-evidence">
        <?php endif; ?>

        <hr style="border-color: #30363d; margin: 20px 0;">
        
        <form method="POST">
            <input type="hidden" name="finding_id" value="<?= $f['id'] ?>">
            <label>Ubah Status:</label>
            <select name="status">
                <option value="open" <?= $f['status']=='open'?'selected':'' ?>>OPEN (Belum Diperbaiki)</option>
                <option value="in-progress" <?= $f['status']=='in-progress'?'selected':'' ?>>IN-PROGRESS (Sedang Diperbaiki)</option>
                <option value="fixed" <?= $f['status']=='fixed'?'selected':'' ?>>FIXED (Sudah Diperbaiki)</option>
            </select>
            <button type="submit" name="update_status">Simpan Status</button>
        </form>
    </div>
    </body></html>
    <?php exit;
}
?>

<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VEXALITHRA</title>
    <style>
        body { font-family: sans-serif; background: #0a0e14; color: #c9d1d9; margin: 0; padding: 20px; }
        .card { background: #161b22; border: 1px solid #30363d; padding: 20px; border-radius: 8px; max-width: 800px; margin: 0 auto 20px auto; }
        input, select, textarea { width: 100%; padding: 10px; margin: 8px 0; background: #0d1117; border: 1px solid #30363d; color: white; border-radius: 5px; box-sizing: border-box; font-family: inherit;}
        button { width: 100%; padding: 10px; background: #58a6ff; color: #000; border: none; border-radius: 5px; font-weight: bold; cursor: pointer; }
        .btn-member { background: #3fb950; }
        h2 { text-align: center; color: #58a6ff; margin-top:0; }
        a { display: block; text-align: center; padding: 12px; margin: 10px 0; text-decoration: none; border-radius: 6px; font-weight: bold; }
        .link-admin { background: #58a6ff; color: #000; }
        .link-member { background: #161b22; border: 1px solid #30363d; color: #c9d1d9; }
        .nav { max-width: 800px; margin: 0 auto 20px auto; display: flex; gap: 15px; flex-wrap: wrap; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
        .nav a { display: inline; margin: 0; padding: 0; color: #58a6ff; text-decoration: none; font-weight: normal; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #30363d; }
        th { color: #7d8590; }
        .msg { background: #3fb95022; color: #3fb950; padding: 10px; border-radius: 5px; border: 1px solid #3fb95066; margin-bottom: 10px; text-align:center; }
        .error { background: #f8514922; color: #f85149; padding: 10px; border-radius: 5px; border: 1px solid #f8514966; margin-bottom: 10px; text-align:center; }
        .badge { font-size: 10px; padding: 2px 6px; border-radius: 4px; font-weight: bold; color: #000;}
        .bg-critical { background: #f85149; color: white; } .bg-high { background: #d29922; } .bg-medium { background: #58a6ff; } .bg-low { background: #3fb950; }
        .form-group { display: flex; gap: 10px; } .form-group > * { flex: 1; }
    </style>
</head>
<body>

<?php if (!is_login()): ?>
    <!-- LOGIN PAGE -->
    <?php if ($page === 'home'): ?>
        <div class="card" style="margin-top: 50px; max-width:400px;"><h2>VEXALITHRA</h2><p style="text-align:center; color:#7d8590; margin-bottom:20px;">Pilih portal masuk:</p><a href="?page=admin" class="link-admin">🛡️ Portal Admin</a><a href="?page=member" class="link-member">👤 Portal Anggota</a></div>
    <?php elseif ($page === 'admin'): ?>
        <div class="card" style="margin-top: 50px; max-width:400px;"><h2>PORTAL ADMIN</h2><?php if(isset($error)) echo "<div class='error'>$error</div>"; ?><form method="POST"><input type="hidden" name="portal" value="admin"><input type="text" name="username" placeholder="Username Admin" required><input type="password" name="password" placeholder="Password" required><button type="submit" name="login">Masuk</button></form><a href="index.php" style="color:#7d8590; font-size:12px; margin-top:15px;">← Kembali</a></div>
    <?php elseif ($page === 'member'): ?>
        <div class="card" style="margin-top: 50px; max-width:400px;"><h2 style="color: #3fb950;">PORTAL ANGGOTA</h2><?php if(isset($error)) echo "<div class='error'>$error</div>"; ?><form method="POST"><input type="hidden" name="portal" value="member"><input type="text" name="username" placeholder="Username" required><input type="password" name="password" placeholder="Password" required><button type="submit" name="login" class="btn-member">Masuk</button></form><a href="index.php" style="color:#7d8590; font-size:12px; margin-top:15px;">← Kembali</a></div>
    <?php endif; ?>

<?php else: ?>
    <!-- DASHBOARD & MENUS -->
    <div class="nav">
        <a href="index.php">Dashboard</a>
        <?php if (is_admin()): ?>
            <a href="?page=targets">Target</a>
            <a href="?page=members">Anggota</a>
        <?php endif; ?>
        <a href="?page=findings">Temuan</a>
        <a href="?logout=1" style="color:#f85149; margin-left:auto;">Logout</a>
    </div>

    <?php if ($page === 'targets' && is_admin()): ?>
        <div class="card">
            <h2>Kelola Target</h2>
            <?php if(isset($msg_target)) echo "<div class='msg'>$msg_target</div>"; ?>
            <form method="POST" style="border-bottom: 1px solid #30363d; padding-bottom: 15px; margin-bottom: 15px;">
                <h3 style="margin-top:0; font-size:14px;">Tambah Target</h3>
                <input type="text" name="name" placeholder="Nama Target" required><input type="text" name="url" placeholder="URL" required><input type="text" name="owner" placeholder="Pemilik">
                <select name="permission_status"><option value="pending">Pending</option><option value="granted">Granted</option></select>
                <button type="submit" name="add_target">Tambah Target</button>
            </form>
            <table><tr><th>Nama</th><th>URL</th><th>Izin</th><th>Aksi</th></tr>
                <?php foreach ($targets as $t): ?><tr><td><?= h($t['name']) ?></td><td><?= h($t['url']) ?></td><td><?= $t['permission_status'] ?></td><td><a href="?page=print_report&target_id=<?= $t['id'] ?>" target="_blank" style="color:#3fb950; font-weight:bold; padding:0; margin:0; display:inline;">📄 Cetak</a></td></tr><?php endforeach; ?>
            </table>
        </div>

    <?php elseif ($page === 'members' && is_admin()): ?>
        <div class="card">
            <h2>Kelola Anggota</h2>
            <?php if(isset($msg_member)) echo "<div class='msg'>$msg_member</div>"; if(isset($error_member)) echo "<div class='error'>$error_member</div>"; ?>
            <form method="POST" style="border-bottom: 1px solid #30363d; padding-bottom: 15px; margin-bottom: 15px;">
                <h3 style="margin-top:0; font-size:14px;">Tambah Anggota</h3>
                <input type="text" name="username" placeholder="Username" required><input type="text" name="display_name" placeholder="Nama Tampilan"><input type="password" name="password" placeholder="Password" required>
                <select name="role"><option value="pentester">Pentester</option><option value="lead">Lead</option></select>
                <button type="submit" name="add_member">Tambah</button>
            </form>
            <table><tr><th>Username</th><th>Nama</th><th>Role</th><th>Aksi</th></tr>
                <?php foreach ($members as $m): ?>
                <tr>
                    <td><?= h($m['username']) ?></td><td><?= h($m['display_name']) ?></td><td><?= $m['role'] ?></td>
                    <td><?php if($m['id'] != $_SESSION['user_id']): ?><a href="?page=members&delete_member=<?= $m['id'] ?>" onclick="return confirm('Hapus anggota ini?')" style="color:#f85149; display:inline; padding:0; margin:0;">Hapus</a><?php endif; ?></td>
                </tr>
                <?php endforeach; ?>
            </table>
        </div>

    <?php elseif ($page === 'findings'): ?>
        <div class="card">
            <h2>Daftar Temuan</h2>
            <?php if(isset($msg_finding)) echo "<div class='msg'>$msg_finding</div>"; ?>
            <?php if(isset($msg_scan)) echo "<div class='msg' style='background:#58a6ff22; color:#58a6ff; border-color:#58a6ff66;'>$msg_scan</div>"; ?>
            
            <!-- FITUR SCANNER OTOMATIS -->
            <?php if (is_pentester()): ?>
            <div style="background: #1c2128; padding: 15px; border-radius: 8px; margin-bottom: 20px; border: 1px dashed #58a6ff;">
                <h3 style="margin-top:0; color:#58a6ff;">Pindai Otomatis (Scanner)</h3>
                <form method="POST" style="display:flex; gap:10px;">
                    <select name="scan_target_id" required style="flex:1; margin:0;">
                        <option value="">-- Pilih Target (Granted) --</option>
                        <?php foreach ($targets as $t): if ($t['permission_status'] === 'granted') echo "<option value='{$t['id']}'>".h($t['name'])."</option>"; endforeach; ?>
                    </select>
                    <button type="submit" name="run_scan" style="width:auto; margin:0;">🔍 Jalankan Scan</button>
        
