<?php
/**
 * Blacklist API — InfinityFree Compatible
 * ใช้ GET + POST เท่านั้น (ไม่ใช้ PUT/DELETE/custom headers)
 * Token ส่งผ่าน POST body หรือ GET param
 */

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

define('DB_FILE',      __DIR__ . '/blacklist.sqlite');
define('ROBLOX_KEY',   'RBX-9kZ#mQ2@vLp!wXr7$NdT');
define('SUPERADMIN',   'MaCorl');
define('TOKEN_EXPIRE', 86400);
define('OPENCLOUD_KEY', 'ใส่ API Key ที่ได้จาก Roblox');
define('UNIVERSE_ID',   '10041445506');

function getDB(): PDO {
    static $pdo = null;
    if ($pdo) return $pdo;
    $pdo = new PDO('sqlite:' . DB_FILE);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec("PRAGMA journal_mode=WAL");
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            is_super INTEGER NOT NULL DEFAULT 0,
            created_by TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS banned_users (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL UNIQUE,
            name TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT 'ไม่ระบุ',
            banned_by TEXT,
            banned_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            unbanned INTEGER NOT NULL DEFAULT 0,
            unbanned_by TEXT,
            unbanned_at TEXT
        );
        CREATE TABLE IF NOT EXISTS banned_groups (
            id TEXT PRIMARY KEY,
            group_id INTEGER NOT NULL UNIQUE,
            name TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT 'ไม่ระบุ',
            banned_by TEXT,
            banned_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            unbanned INTEGER NOT NULL DEFAULT 0,
            unbanned_by TEXT,
            unbanned_at TEXT
        );
        CREATE TABLE IF NOT EXISTS action_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT,
            detail TEXT,
            ts TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        );
    ");
    $n = $pdo->query("SELECT COUNT(*) FROM admins WHERE username='".SUPERADMIN."'")->fetchColumn();
    if (!$n) {
        $hash = password_hash('MaCorl@S3cur3!#2025', PASSWORD_BCRYPT, ['cost'=>12]);
        $pdo->prepare("INSERT INTO admins (username,password,is_super,created_by) VALUES (?,?,1,'system')")
            ->execute([SUPERADMIN, $hash]);
    }
    return $pdo;
}

function out($d, int $c=200): void {
    http_response_code($c);
    echo json_encode($d, JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT);
    exit;
}
function body(): array {
    static $b = null;
    if ($b !== null) return $b;
    $raw = file_get_contents('php://input');
    $b = json_decode($raw, true) ?? [];
    return $b;
}
function getToken(): string {
    $b = body();
    return $b['token'] ?? $_GET['token'] ?? '';
}
function getRobloxKey(): string {
    return $_GET['key'] ?? body()['key'] ?? '';
}
function newId(): string { return bin2hex(random_bytes(8)); }
function logAction(string $actor, string $action, string $target='', string $detail=''): void {
    getDB()->prepare("INSERT INTO action_log (actor,action,target,detail) VALUES (?,?,?,?)")
           ->execute([$actor,$action,$target,$detail]);
}
function requireRoblox(): void {
    if (getRobloxKey() !== ROBLOX_KEY) out(['error'=>'Unauthorized'], 403);
}
function requireAdmin(): array {
    $token = getToken();
    if (!$token) out(['error'=>'No token'], 401);
    $db = getDB();
    $s  = $db->prepare("SELECT username,expires_at FROM sessions WHERE token=?");
    $s->execute([$token]);
    $sess = $s->fetch(PDO::FETCH_ASSOC);
    if (!$sess || $sess['expires_at'] < time()) out(['error'=>'Session expired'], 401);
    $db->prepare("UPDATE sessions SET expires_at=? WHERE token=?")->execute([time()+TOKEN_EXPIRE,$token]);
    $a = $db->prepare("SELECT username,is_super FROM admins WHERE username=?");
    $a->execute([$sess['username']]);
    $admin = $a->fetch(PDO::FETCH_ASSOC);
    if (!$admin) out(['error'=>'Admin not found'], 401);
    return $admin;
}
function requireSuper(): array {
    $a = requireAdmin();
    if (!$a['is_super']) out(['error'=>'Superadmin only'], 403);
    return $a;
}

$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? body()['action'] ?? '';

// ── LOGIN ──────────────────────────────────────────────
if ($action==='login' && $method==='POST') {
    $b = body();
    $user = trim($b['username'] ?? '');
    $pass = trim($b['password'] ?? '');
    if (!$user||!$pass) out(['error'=>'ใส่ username และ password'],400);
    $db  = getDB();
    $row = $db->prepare("SELECT username,password,is_super FROM admins WHERE username=?");
    $row->execute([$user]);
    $adm = $row->fetch(PDO::FETCH_ASSOC);
    if (!$adm||!password_verify($pass,$adm['password'])) out(['error'=>'ชื่อหรือรหัสผ่านไม่ถูกต้อง'],401);
    $db->prepare("DELETE FROM sessions WHERE username=?")->execute([$user]);
    $token = bin2hex(random_bytes(32));
    $db->prepare("INSERT INTO sessions (token,username,expires_at) VALUES (?,?,?)")
       ->execute([$token,$user,time()+TOKEN_EXPIRE]);
    logAction($user,'login');
    out(['token'=>$token,'username'=>$user,'is_super'=>(bool)$adm['is_super']]);
}

if ($action==='logout' && $method==='POST') {
    $t = getToken();
    if ($t) getDB()->prepare("DELETE FROM sessions WHERE token=?")->execute([$t]);
    out(['success'=>true]);
}

if ($action==='me' && $method==='GET') {
    out(requireAdmin());
}

// ── ROBLOX ────────────────────────────────────────────
if ($action==='list' && $method==='GET') {
    requireRoblox();
    $db = getDB();
    $users  = $db->query("SELECT user_id AS userId,name,reason FROM banned_users  WHERE unbanned=0")->fetchAll(PDO::FETCH_ASSOC);
    $groups = $db->query("SELECT group_id AS groupId,name,reason FROM banned_groups WHERE unbanned=0")->fetchAll(PDO::FETCH_ASSOC);
    foreach ($users  as &$u) $u['userId']  = (int)$u['userId'];
    foreach ($groups as &$g) $g['groupId'] = (int)$g['groupId'];
    out(['users'=>$users,'groups'=>$groups]);
}

// ── ADMIN LIST / STATS ────────────────────────────────
if ($action==='admin_list' && $method==='GET') {
    $me = requireAdmin();
    $db = getDB();
    $users  = $db->query("SELECT id,user_id,name,reason,banned_by,banned_at,unbanned,unbanned_by,unbanned_at FROM banned_users  ORDER BY banned_at DESC")->fetchAll(PDO::FETCH_ASSOC);
    $groups = $db->query("SELECT id,group_id,name,reason,banned_by,banned_at,unbanned,unbanned_by,unbanned_at FROM banned_groups ORDER BY banned_at DESC")->fetchAll(PDO::FETCH_ASSOC);
    foreach ($users  as &$u) { $u['user_id']=(int)$u['user_id'];   $u['unbanned']=(bool)$u['unbanned']; }
    foreach ($groups as &$g) { $g['group_id']=(int)$g['group_id']; $g['unbanned']=(bool)$g['unbanned']; }
    out(['users'=>$users,'groups'=>$groups,'me'=>$me]);
}

if ($action==='stats' && $method==='GET') {
    requireAdmin();
    $db  = getDB();
    $tu  = $db->query("SELECT COUNT(*) FROM banned_users  WHERE unbanned=0")->fetchColumn();
    $tg  = $db->query("SELECT COUNT(*) FROM banned_groups WHERE unbanned=0")->fetchColumn();
    $rec = $db->query("
        SELECT 'user' AS type,name,user_id  AS eid,reason,banned_at AS ts,banned_by FROM banned_users  WHERE unbanned=0
        UNION ALL
        SELECT 'group',name,      group_id AS eid,reason,banned_at AS ts,banned_by FROM banned_groups WHERE unbanned=0
        ORDER BY ts DESC LIMIT 10
    ")->fetchAll(PDO::FETCH_ASSOC);
    out(['totalUsers'=>(int)$tu,'totalGroups'=>(int)$tg,'recent'=>$rec]);
}

// ── BAN USER ──────────────────────────────────────────
if ($action==='add_user' && $method==='POST') {
    $me     = requireAdmin();
    $b      = body();
    $userId = intval($b['userId'] ?? 0);
    $reason = trim($b['reason'] ?? 'ไม่ระบุ');
    $name   = trim($b['name']   ?? '');
    if (!$userId) out(['error'=>'userId required'],400);
    $db    = getDB();
    $exist = $db->prepare("SELECT id,unbanned FROM banned_users WHERE user_id=?");
    $exist->execute([$userId]);
    $row = $exist->fetch(PDO::FETCH_ASSOC);
    if ($row && !$row['unbanned']) out(['error'=>'already in blacklist']);
    if ($row && $row['unbanned']) {
        $db->prepare("UPDATE banned_users SET reason=?,name=?,banned_by=?,banned_at=datetime('now','localtime'),unbanned=0,unbanned_by=NULL,unbanned_at=NULL WHERE user_id=?")
           ->execute([$reason,$name,$me['username'],$userId]);
    } else {
        $db->prepare("INSERT INTO banned_users (id,user_id,name,reason,banned_by) VALUES (?,?,?,?,?)")
           ->execute([newId(),$userId,$name,$reason,$me['username']]);
    }
    logAction($me['username'],'ban_user',(string)$userId,$reason);
    syncToRoblox($userId, true, $reason);
    out(['success'=>true]);
}

// ── UNBAN USER (POST) ─────────────────────────────────
if ($action==='unban_user' && $method==='POST') {
    $me = requireAdmin();
    $b  = body();
    $id = $b['id'] ?? '';
    if (!$id) out(['error'=>'id required'],400);
    getDB()->prepare("UPDATE banned_users SET unbanned=1,unbanned_by=?,unbanned_at=datetime('now','localtime') WHERE id=?")
           ->execute([$me['username'],$id]);
    logAction($me['username'],'unban_user',$id);
    $row2 = getDB()->prepare("SELECT user_id FROM banned_users WHERE id=?");
    $row2->execute([$id]);
    $uid = (int)($row2->fetchColumn() ?: 0);
    if ($uid) syncToRoblox($uid, false);
    out(['success'=>true]);
}

// ── DELETE USER (POST) ────────────────────────────────
if ($action==='remove_user' && $method==='POST') {
    $me = requireAdmin();
    $b  = body();
    $id = $b['id'] ?? '';
    getDB()->prepare("DELETE FROM banned_users WHERE id=?")->execute([$id]);
    logAction($me['username'],'delete_user',$id);
    out(['success'=>true]);
}

// ── BAN GROUP ─────────────────────────────────────────
if ($action==='add_group' && $method==='POST') {
    $me      = requireAdmin();
    $b       = body();
    $groupId = intval($b['groupId'] ?? 0);
    $reason  = trim($b['reason'] ?? 'ไม่ระบุ');
    $name    = trim($b['name']   ?? '');
    if (!$groupId) out(['error'=>'groupId required'],400);
    $db    = getDB();
    $exist = $db->prepare("SELECT id,unbanned FROM banned_groups WHERE group_id=?");
    $exist->execute([$groupId]);
    $row = $exist->fetch(PDO::FETCH_ASSOC);
    if ($row && !$row['unbanned']) out(['error'=>'already in blacklist']);
    if ($row && $row['unbanned']) {
        $db->prepare("UPDATE banned_groups SET reason=?,name=?,banned_by=?,banned_at=datetime('now','localtime'),unbanned=0,unbanned_by=NULL,unbanned_at=NULL WHERE group_id=?")
           ->execute([$reason,$name,$me['username'],$groupId]);
    } else {
        $db->prepare("INSERT INTO banned_groups (id,group_id,name,reason,banned_by) VALUES (?,?,?,?,?)")
           ->execute([newId(),$groupId,$name,$reason,$me['username']]);
    }
    logAction($me['username'],'ban_group',(string)$groupId,$reason);
    out(['success'=>true]);
}

// ── UNBAN GROUP (POST) ────────────────────────────────
if ($action==='unban_group' && $method==='POST') {
    $me = requireAdmin();
    $b  = body();
    $id = $b['id'] ?? '';
    if (!$id) out(['error'=>'id required'],400);
    getDB()->prepare("UPDATE banned_groups SET unbanned=1,unbanned_by=?,unbanned_at=datetime('now','localtime') WHERE id=?")
           ->execute([$me['username'],$id]);
    logAction($me['username'],'unban_group',$id);
    out(['success'=>true]);
}

// ── DELETE GROUP (POST) ───────────────────────────────
if ($action==='remove_group' && $method==='POST') {
    $me = requireAdmin();
    $b  = body();
    $id = $b['id'] ?? '';
    getDB()->prepare("DELETE FROM banned_groups WHERE id=?")->execute([$id]);
    logAction($me['username'],'delete_group',$id);
    out(['success'=>true]);
}

// ── ADMIN MANAGEMENT ──────────────────────────────────
if ($action==='admin_users' && $method==='GET') {
    requireSuper();
    $list = getDB()->query("SELECT id,username,is_super,created_by,created_at FROM admins ORDER BY id")->fetchAll(PDO::FETCH_ASSOC);
    foreach ($list as &$a) $a['is_super']=(bool)$a['is_super'];
    out($list);
}

if ($action==='add_admin' && $method==='POST') {
    $me   = requireSuper();
    $b    = body();
    $user = trim($b['username'] ?? '');
    $pass = trim($b['password'] ?? '');
    if (!$user||!$pass) out(['error'=>'username/password required'],400);
    if (strlen($pass)<12) out(['error'=>'รหัสผ่านต้องมีอย่างน้อย 12 ตัวอักษร'],400);
    $hash = password_hash($pass,PASSWORD_BCRYPT,['cost'=>12]);
    try {
        getDB()->prepare("INSERT INTO admins (username,password,is_super,created_by) VALUES (?,?,0,?)")
               ->execute([$user,$hash,$me['username']]);
        logAction($me['username'],'add_admin',$user);
        out(['success'=>true]);
    } catch (PDOException) {
        out(['error'=>'ชื่อนี้มีอยู่แล้ว'],409);
    }
}

if ($action==='remove_admin' && $method==='POST') {
    $me   = requireSuper();
    $b    = body();
    $user = trim($b['username'] ?? '');
    if ($user===SUPERADMIN) out(['error'=>'ลบ superadmin ไม่ได้'],403);
    $db = getDB();
    $db->prepare("DELETE FROM sessions WHERE username=?")->execute([$user]);
    $db->prepare("DELETE FROM admins   WHERE username=? AND is_super=0")->execute([$user]);
    logAction($me['username'],'remove_admin',$user);
    out(['success'=>true]);
}

if ($action==='change_password' && $method==='POST') {
    $me  = requireAdmin();
    $b   = body();
    $old = trim($b['old_password'] ?? '');
    $new = trim($b['new_password'] ?? '');
    if (strlen($new)<12) out(['error'=>'รหัสผ่านต้องมีอย่างน้อย 12 ตัวอักษร'],400);
    $db  = getDB();
    $row = $db->prepare("SELECT password FROM admins WHERE username=?");
    $row->execute([$me['username']]);
    $adm = $row->fetch(PDO::FETCH_ASSOC);
    if (!$adm||!password_verify($old,$adm['password'])) out(['error'=>'รหัสผ่านเดิมไม่ถูกต้อง'],401);
    $db->prepare("UPDATE admins SET password=? WHERE username=?")
       ->execute([password_hash($new,PASSWORD_BCRYPT,['cost'=>12]),$me['username']]);
    logAction($me['username'],'change_password');
    out(['success'=>true]);
}

// ── LOG ───────────────────────────────────────────────
if ($action==='log' && $method==='GET') {
    requireSuper();
    $log = getDB()->query("SELECT * FROM action_log ORDER BY id DESC LIMIT 200")->fetchAll(PDO::FETCH_ASSOC);
    out($log);
}


// ── SYNC TO ROBLOX ────────────────────────────────────
function syncToRoblox(int $userId, bool $ban, string $reason = ''): bool {
    $url  = sprintf(
        'https://apis.roblox.com/cloud/v2/universes/%s/user-restrictions/%d',
        UNIVERSE_ID, $userId
    );
    $body = json_encode([
        'gameJoinRestriction' => [
            'active'             => $ban,
            'privateReason'      => $reason ?: 'Blacklisted',
            'displayReason'      => "🔴 [Ghost X System]\n📌 เหตุผล: " . ($reason ?: 'ไม่ระบุ'),
            'excludeAltAccounts' => false,
        ]
    ]);
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST  => 'PATCH',
        CURLOPT_POSTFIELDS     => $body,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => [
            'x-api-key: ' . OPENCLOUD_KEY,
            'Content-Type: application/json',
        ],
    ]);
    $res  = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return $code === 200;
}

out(['error'=>'not found'], 404);
