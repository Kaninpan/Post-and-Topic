<?php
session_start();

if (!isset($_SESSION['initiated'])) {
    session_regenerate_id(true);
    $_SESSION['initiated'] = time();
}
if(empty($_SESSION['csrf_token'])){
    try{
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }catch(Throwable $e){
        $_SESSION['csrf_token'] = bin2hex(openssl_random_pseudo_bytes(32));
    }
}

date_default_timezone_set('Asia/Bangkok');

function validateCsrf($token){
    return isset($_SESSION['csrf_token']) && is_string($token) && hash_equals($_SESSION['csrf_token'], $token);
}

if (!isset($_SESSION['user_name'])) {
    if(isset($_POST['set_name']) && !empty($_POST['set_name'])){
        if(!validateCsrf($_POST['csrf_token'] ?? null)){
            http_response_code(403);
            echo "ERROR"; exit;
        }
        $name = trim($_POST['set_name']);
        $name = preg_replace('/\s+/', ' ', $name);
        if(mb_strlen($name) > 64) $name = mb_substr($name,0,64);

        if(isset($_FILES['avatar']) && is_uploaded_file($_FILES['avatar']['tmp_name'])){
            $allowedMax = 2 * 1024 * 1024;
            $f = $_FILES['avatar'];
            if($f['size'] > 0 && $f['size'] <= $allowedMax){
                $info = @getimagesize($f['tmp_name']);
                if($info && in_array($info[2], [IMAGETYPE_GIF, IMAGETYPE_JPEG, IMAGETYPE_PNG], true)){
                    $ext = image_type_to_extension($info[2], false);
                    $safe_key = sha1(mb_strtolower($name, 'UTF-8'));
                    $avatars_dir = __DIR__ . '/avatars';
                    if(!is_dir($avatars_dir)) @mkdir($avatars_dir, 0755, true);
                    foreach (glob($avatars_dir . '/' . $safe_key . '.*') as $old) { @unlink($old); }
                    $target = $avatars_dir . '/' . $safe_key . '.' . $ext;
                    if(move_uploaded_file($f['tmp_name'], $target)){
                        $_SESSION['avatar_file'] = 'avatars/' . $safe_key . '.' . $ext;
                    }
                }
            }
        }

        $_SESSION['user_name'] = htmlspecialchars($name, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8');
        session_regenerate_id(true);
    } else {
        ?>
        <!DOCTYPE html>
        <html lang="th">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>กรุณากรอกชื่อผู้ใช้</title>
            <link href="https://fonts.googleapis.com/css2?family=Prompt:wght@300;400;500;600;700&display=swap" rel="stylesheet">
            <style>
            *{margin:0;padding:0;box-sizing:border-box}
            body{font-family:'Prompt',system-ui,-apple-system,sans-serif;background:#f0f2f5;min-height:100vh;display:flex;align-items:center;justify-content:center}
            .login-card{background:#fff;border-radius:16px;box-shadow:0 2px 12px rgba(0,0,0,0.08);padding:40px;width:100%;max-width:420px}
            .login-logo{text-align:center;margin-bottom:24px}
            .login-logo h1{color:#1877f2;font-size:36px;font-weight:700;letter-spacing:-1px}
            .login-logo p{color:#65676b;font-size:15px;margin-top:4px}
            .form-group{margin-bottom:16px}
            .form-group label{display:block;font-size:13px;font-weight:600;color:#65676b;margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px}
            .form-group input[type="text"]{width:100%;padding:12px 16px;border:1px solid #dddfe2;border-radius:8px;font-size:15px;font-family:inherit;transition:border-color .2s,box-shadow .2s;background:#f5f6f7}
            .form-group input[type="text"]:focus{outline:none;border-color:#1877f2;box-shadow:0 0 0 2px rgba(24,119,242,0.15);background:#fff}
            .form-group input[type="file"]{width:100%;padding:10px;border:1px dashed #dddfe2;border-radius:8px;font-size:14px;font-family:inherit;background:#f5f6f7;cursor:pointer}
            .form-group input[type="file"]:hover{border-color:#1877f2;background:#eef3ff}
            .avatar-preview{width:80px;height:80px;border-radius:50%;object-fit:cover;margin:8px auto;display:none;border:3px solid #e4e6eb}
            .avatar-preview-wrap{text-align:center}
            .btn-submit{width:100%;padding:12px;background:#1877f2;color:#fff;border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer;transition:background .2s;font-family:inherit;margin-top:8px}
            .btn-submit:hover{background:#166fe5}
            </style>
        </head>
        <body>
            <div class="login-card">
                <div class="login-logo">
                    <h1>MiniSocial</h1>
                    <p>เข้าสู่ระบบเพื่อเริ่มต้นใช้งาน</p>
                </div>
                <form method="POST" enctype="multipart/form-data">
                    <div class="form-group">
                        <label>ชื่อของคุณ</label>
                        <input type="text" name="set_name" id="set_name" required placeholder="กรอกชื่อที่ต้องการแสดง" maxlength="64" autocomplete="name">
                    </div>
                    <div class="form-group">
                        <label>รูปโปรไฟล์ (ไม่บังคับ, สูงสุด 2MB)</label>
                        <input type="file" name="avatar" id="avatar" accept="image/*">
                        <div class="avatar-preview-wrap">
                            <img class="avatar-preview" id="avatarPreview" alt="preview">
                        </div>
                    </div>
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                    <button type="submit" class="btn-submit">เข้าสู่ระบบ</button>
                </form>
            </div>
            <script>
            (function(){
                var avatarInput = document.getElementById('avatar');
                var preview = document.getElementById('avatarPreview');
                var MAX_AVATAR = 2 * 1024 * 1024;
                avatarInput.addEventListener('change', function(){
                    var f = this.files && this.files[0];
                    if(f && f.size > MAX_AVATAR){
                        alert('ไฟล์รูปโปรไฟล์มีขนาดเกินที่กำหนด (2MB). กรุณาเลือกไฟล์ขนาดเล็กกว่า 2MB');
                        this.value = '';
                        preview.style.display='none';
                        return;
                    }
                    if(f && f.type.startsWith('image/')){
                        var reader = new FileReader();
                        reader.onload = function(e){ preview.src = e.target.result; preview.style.display='block'; };
                        reader.readAsDataURL(f);
                    }
                });
            })();
            </script>
        </body>
        </html>
        <?php
        exit;
    }
}

function getAvatarUrlForUser($username){
    $key = sha1(mb_strtolower((string)$username, 'UTF-8'));
    $dir = __DIR__ . '/avatars';
    if(!is_dir($dir)) return null;
    $found = glob($dir . '/' . $key . '.*');
    if($found && count($found)){
        $file = basename($found[0]);
        return 'avatars/' . $file;
    }
    return null;
}

function handleUploadedMedia($fileField = 'media'){
    if(empty($_FILES[$fileField]) || !is_uploaded_file($_FILES[$fileField]['tmp_name'])) return null;
    $f = $_FILES[$fileField];
    $allowedMax = 8 * 1024 * 1024;
    if($f['size'] <= 0 || $f['size'] > $allowedMax) return null;

    $finfo = @finfo_open(FILEINFO_MIME_TYPE);
    $mime = $finfo ? @finfo_file($finfo, $f['tmp_name']) : null;
    if($finfo) @finfo_close($finfo);

    $isImageInfo = @getimagesize($f['tmp_name']);
    if(!$mime && $isImageInfo) $mime = $isImageInfo['mime'] ?? null;
    if(!$mime) return null;

    $mime = strtolower($mime);
    $imageMimes = ['image/jpeg','image/png','image/gif','image/webp'];
    $videoMimes = ['video/mp4','video/webm','video/ogg'];

    if(in_array($mime, $imageMimes, true)){
        $map = ['image/jpeg'=>'jpg','image/png'=>'png','image/gif'=>'gif','image/webp'=>'webp'];
        $ext = $map[$mime] ?? 'img';
        $kind = ($mime === 'image/gif') ? 'gif' : 'image';
    } elseif(in_array($mime, $videoMimes, true)){
        $map = ['video/mp4'=>'mp4','video/webm'=>'webm','video/ogg'=>'ogv'];
        $ext = $map[$mime] ?? 'vid';
        $kind = 'video';
    } else {
        return null;
    }

    $uploads_dir = __DIR__ . '/uploads';
    if(!is_dir($uploads_dir)) @mkdir($uploads_dir, 0755, true);

    $name = uniqid('m_', true) . '.' . $ext;
    $target = $uploads_dir . '/' . $name;
    if(!@move_uploaded_file($f['tmp_name'], $target)) return null;

    return ['path' => 'uploads/' . $name, 'kind' => $kind, 'mime' => $mime, 'ext' => $ext];
}

$data_file = "data.json";
if(file_exists($data_file)){
    $raw = file_get_contents($data_file);
    $data = json_decode($raw, true);
    if(json_last_error() !== JSON_ERROR_NONE || !is_array($data)) {
        $data = ["posts"=>[]];
    }
}else{
    $data = ["posts"=>[]];
}

function saveData($file, $data){
    $json = json_encode($data, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE);
    if($json === false) return false;
    return file_put_contents($file, $json, LOCK_EX) !== false;
}

function getClientIP(){
    $candidates = [];
    if(!empty($_SERVER['HTTP_X_FORWARDED_FOR'])){
        $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        foreach($parts as $p){
            $ip = trim($p);
            $ip = preg_replace('/%.+$/', '', $ip);
            $ip = preg_replace('/:\d+$/', '', $ip);
            if($ip !== '') $candidates[] = $ip;
        }
    }
    if(!empty($_SERVER['HTTP_CLIENT_IP'])){
        $ip = trim($_SERVER['HTTP_CLIENT_IP']);
        $ip = preg_replace('/%.+$/', '', $ip);
        $ip = preg_replace('/:\d+$/', '', $ip);
        if($ip !== '') $candidates[] = $ip;
    }
    if(!empty($_SERVER['REMOTE_ADDR'])){
        $ip = trim($_SERVER['REMOTE_ADDR']);
        $ip = preg_replace('/%.+$/', '', $ip);
        $ip = preg_replace('/:\d+$/', '', $ip);
        if($ip !== '') $candidates[] = $ip;
    }
    foreach($candidates as $ip){
        if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return $ip;
    }
    foreach($candidates as $ip){
        if(filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
    }
    return '0.0.0.0';
}

function checkRateLimit($key, $limitSeconds){
    $now = time();
    if(!isset($_SESSION['rate'][$key]) || ($now - $_SESSION['rate'][$key]) >= $limitSeconds){
        $_SESSION['rate'][$key] = $now;
        return true;
    }
    return false;
}

function &findCommentByTimeRecursive(&$comments, $time){
    $null = null;
    foreach ($comments as &$c) {
        if ((int)$c['time'] === (int)$time) return $c;
        if (!empty($c['replies'])) {
            $found = &findCommentByTimeRecursive($c['replies'], $time);
            if ($found !== null) return $found;
        }
    }
    return $null;
}

function deleteCommentRecursive(&$comments, $time){
    foreach ($comments as $idx => &$c) {
        if ((int)$c['time'] === (int)$time) {
            array_splice($comments, $idx, 1);
            return true;
        }
        if (!empty($c['replies'])) {
            if (deleteCommentRecursive($c['replies'], $time)) return true;
        }
    }
    return false;
}

function timeAgo($timestamp){
    $diff = time() - $timestamp;
    if($diff < 60) return 'เมื่อสักครู่';
    if($diff < 3600) return floor($diff/60) . ' นาทีที่แล้ว';
    if($diff < 86400) return floor($diff/3600) . ' ชั่วโมงที่แล้ว';
    if($diff < 604800) return floor($diff/86400) . ' วันที่แล้ว';
    return date("d/m/Y", $timestamp);
}

function renderComments($comments, $post_id, $level = 0){
    foreach ($comments as $c) {
        $cReacts = $c['reactions'] ?? ["like"=>[],"love"=>[],"wow"=>[],"angry"=>[]];
        $indent = min($level, 3) * 12;
        $cid = (int)$c['time'];
        $replies = $c['replies'] ?? [];
        $totalReplies = count($replies);
        $fullText = (string)($c['text'] ?? '');
        $shortLimit = 300;
        $isLong = mb_strlen($fullText) > $shortLimit;
        $shortText = $isLong ? mb_substr($fullText, 0, $shortLimit) : $fullText;
        $avatarUrl = getAvatarUrlForUser($c['user']);
        $reactCounts = [];
        foreach(["like","love","wow","angry"] as $rt){
            $n = count($cReacts[$rt]??[]);
            if($n > 0) $reactCounts[$rt] = $n;
        }
        $totalReacts = array_sum($reactCounts);
        ?>
        <div class="fb-comment-row" id="comment_<?= $post_id ?>_<?= $cid ?>" style="margin-left:<?= $indent ?>px">
            <div class="fb-comment-avatar">
                <?php if($avatarUrl): ?>
                    <img src="<?= htmlspecialchars($avatarUrl) ?>" alt="" class="fb-avatar-img">
                <?php else: ?>
                    <div class="fb-avatar-fallback"><?= htmlspecialchars(mb_substr($c['user'],0,1)) ?></div>
                <?php endif; ?>
            </div>
            <div class="fb-comment-body">
                <div class="fb-comment-bubble">
                    <div class="fb-comment-author"><?= htmlspecialchars($c['user']) ?></div>
                    <div class="fb-comment-text">
                        <?php if($isLong): ?>
                            <span id="short_text_<?= $post_id ?>_<?= $cid ?>"><?= htmlspecialchars($shortText) ?>…</span>
                            <span id="full_text_<?= $post_id ?>_<?= cid ?>" style="display:none;white-space:pre-wrap"><?= htmlspecialchars($fullText) ?></span>
                            <span class="fb-read-more" onclick="toggleLongText('<?= $post_id ?>','<?= $cid ?>')" id="read_more_btn_<?= $post_id ?>_<?= $cid ?>">ดูเพิ่มเติม</span>
                        <?php else: ?>
                            <span><?= htmlspecialchars($fullText) ?></span>
                        <?php endif; ?>
                    </div>
                    <?php if(!empty($c['media']) && !empty($c['media']['path'])):
                        $cm = $c['media'];
                        $cpath = htmlspecialchars($cm['path']);
                        if($cm['kind'] === 'video'): ?>
                            <div class="fb-comment-media"><video controls><source src="<?= $cpath ?>" type="<?= htmlspecialchars($cm['mime']) ?>"></video></div>
                        <?php else: ?>
                            <div class="fb-comment-media"><img src="<?= $cpath ?>" alt="media"></div>
                        <?php endif;
                    endif; ?>
                </div>
                <?php if($totalReacts > 0): ?>
                <div class="fb-comment-reacts">
                    <?php foreach(["like"=>"👍","love"=>"❤️","wow"=>"😮","angry"=>"😡"] as $rt=>$em):
                        if(!empty($reactCounts[$rt])): ?>
                        <span class="fb-react-pill"><?= $em ?> <?= $reactCounts[$rt] ?></span>
                    <?php endif; endforeach; ?>
                </div>
                <?php endif; ?>
                <div class="fb-comment-actions">
                    <span class="fb-comment-time"><?= timeAgo((int)$c['time']) ?></span>
                    <?php if($c['user']==$_SESSION['user_name'] || ( ($c['ip'] ?? '') === getClientIP() )): ?>
                        <span class="fb-comment-action" onclick="editComment('<?= $post_id ?>','<?= $cid ?>')">แก้ไข</span>
                        <span class="fb-comment-action fb-action-danger" onclick="deleteComment('<?= $post_id ?>','<?= $cid ?>')">ลบ</span>
                    <?php endif; ?>
                    <span class="fb-comment-action" onclick="replyComment('<?= $post_id ?>','<?= $cid ?>')">ตอบ</span>
                </div>
            </div>
        </div>
        <?php
        if ($totalReplies > 0) {
            $maxShow = 3;
            if ($totalReplies > $maxShow) {
                $hiddenCount = $totalReplies - $maxShow;
                ?>
                <div class="fb-view-more" style="margin-left:<?= $indent ?>px">
                    <span class="fb-view-more-btn" id="replies_toggle_<?= $post_id ?>_<?= $cid ?>" onclick="revealPrevReplies('<?= $post_id ?>','<?= $cid ?>')">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 8l-6 6 1.41 1.41L12 10.83l4.59 4.58L18 14z"/></svg>
                        ดูความคิดเห็นเพิ่มเติมอีก <?= $hiddenCount ?> รายการ
                    </span>
                </div>
                <?php
                echo '<div id="replies_hidden_'.$post_id.'_'.$cid.'" class="replies-hidden">';
                $earlier = array_slice($replies, 0, $hiddenCount, true);
                renderComments($earlier, $post_id, $level + 1);
                echo '</div>';
                $visible = array_slice($replies, -$maxShow, $maxShow, true);
                renderComments($visible, $post_id, $level + 1);
            } else {
                renderComments($replies, $post_id, $level + 1);
            }
        }
    }
}

// API Handlers
if(isset($_POST['api'])){
    header('Content-Type: text/plain; charset=utf-8');
    if(!validateCsrf($_POST['csrf_token'] ?? null)){
        http_response_code(403);
        echo "ERROR"; exit;
    }

    $sanitizeText = function($s, $max=2000){
        $s = mb_substr((string)$s, 0, $max);
        $s = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $s);
        return $s;
    };
    $allowedReactions = ["like","love","wow","angry"];

    if($_POST['api']=="add_post"){
        if(!checkRateLimit('add_post', 5)) { http_response_code(429); echo "ERROR"; exit; }
        $text = $sanitizeText($_POST['text'] ?? '');
        if(trim($text) === "") { echo "ERROR"; exit; }
        $media = handleUploadedMedia('media');
        $newPost = [
            "id"=>uniqid("post_"),
            "user"=>$_SESSION['user_name'],
            "text"=>$text,
            "time"=>time(),
            "ip"=>getClientIP(),
            "reactions"=>["like"=>[],"love"=>[],"wow"=>[],"angry"=>[]],
            "comments"=>[]
        ];
        if($media) $newPost['media'] = $media;
        $data['posts'][] = $newPost;
        saveData($data_file,$data);
        echo "OK"; exit;
    }

    if($_POST['api']=="delete_post"){
        $post_id = $_POST['post_id'] ?? '';
        if(!preg_match('/^post_[a-z0-9]+$/i', $post_id)){ echo "ERROR"; exit; }
        foreach($data['posts'] as $index => $p){
            if($p['id']==$post_id && ( $p['user']==$_SESSION['user_name'] || (($p['ip'] ?? '') === getClientIP()) )){
                array_splice($data['posts'], $index, 1);
                saveData($data_file, $data);
                echo "OK"; exit;
            }
        }
        echo "ERROR"; exit;
    }

    if($_POST['api']=="delete_comment"){
        $post_id = $_POST['post_id'] ?? '';
        $comment_time = $_POST['comment_time'] ?? '';
        if(!preg_match('/^post_[a-z0-9]+$/i', $post_id) || !is_numeric($comment_time)){ echo "ERROR"; exit; }
        foreach($data['posts'] as &$p){
            if($p['id']==$post_id){
                if(deleteCommentRecursive($p['comments'], $comment_time)){
                    saveData($data_file, $data);
                    echo "OK"; exit;
                }
            }
        }
        echo "ERROR"; exit;
    }

    if($_POST['api']=="reaction"){
        $post_id = $_POST['post_id'] ?? '';
        $type = $_POST['type'] ?? '';
        if(!in_array($type, $allowedReactions, true) || !preg_match('/^post_[a-z0-9]+$/i', $post_id)){ echo "ERROR"; exit; }
        foreach($data['posts'] as &$p){
            if($p['id']==$post_id){
                $clicked_same=false;
                foreach($p["reactions"] as $key => &$users){
                    if($key === $type && in_array($_SESSION['user_name'],$users)){
                        $users = array_values(array_diff($users, [$_SESSION['user_name']]));
                        $clicked_same = true;
                    } else {
                        $users = array_values(array_diff($users, [$_SESSION['user_name']]));
                    }
                }
                if(!$clicked_same) $p["reactions"][$type][] = $_SESSION['user_name'];
            }
        }
        saveData($data_file,$data);
        echo "OK"; exit;
    }

    if($_POST['api']=="reaction_comment"){
        $post_id = $_POST['post_id'] ?? '';
        $comment_time = $_POST['comment_time'] ?? '';
        $type = $_POST['type'] ?? '';
        if(!in_array($type, $allowedReactions, true) || !preg_match('/^post_[a-z0-9]+$/i', $post_id) || !is_numeric($comment_time)){ echo "ERROR"; exit; }
        foreach($data['posts'] as &$p){
            if($p['id']==$post_id){
                $c = &findCommentByTimeRecursive($p['comments'], $comment_time);
                if($c !== null){
                    $clicked_same = false;
                    if(!isset($c['reactions'])) $c['reactions'] = ["like"=>[],"love"=>[],"wow"=>[],"angry"=>[]];
                    foreach($c['reactions'] as $key => &$users){
                        if($key === $type && in_array($_SESSION['user_name'],$users)){
                            $users = array_values(array_diff($users, [$_SESSION['user_name']]));
                            $clicked_same = true;
                        } else {
                            $users = array_values(array_diff($users, [$_SESSION['user_name']]));
                        }
                    }
                    if(!$clicked_same) $c['reactions'][$type][] = $_SESSION['user_name'];
                }
            }
        }
        saveData($data_file,$data);
        echo "OK"; exit;
    }

    if($_POST['api']=="comment"){
        if(!checkRateLimit('comment', 2)) { http_response_code(429); echo "ERROR"; exit; }
        $post_id = $_POST['post_id'] ?? '';
        if(!preg_match('/^post_[a-z0-9]+$/i', $post_id)){ echo "ERROR"; exit; }
        foreach($data['posts'] as &$p){
            if($p['id']==$post_id){
                $media = handleUploadedMedia('media');
                $text = $sanitizeText($_POST['text'] ?? '');
                if(trim($text) === "" && !$media) { echo "ERROR"; exit; }
                $comment=[
                    "user"=>$_SESSION['user_name'],
                    "text"=>$text,
                    "time"=>time(),
                    "ip"=>getClientIP(),
                    "reactions"=>["like"=>[],"love"=>[],"wow"=>[],"angry"=>[]],
                    "replies"=>[]
                ];
                if($media) $comment['media'] = $media;
                if(!empty($_POST['parent_time'])){
                    $parent_time = $_POST['parent_time'];
                    if(!is_numeric($parent_time)){ echo "ERROR"; exit; }
                    $parent = &findCommentByTimeRecursive($p['comments'], $parent_time);
                    if($parent !== null){
                        if(!isset($parent['replies'])) $parent['replies'] = [];
                        $parent['replies'][] = $comment;
                        saveData($data_file,$data);
                        header('Content-Type: application/json; charset=utf-8');
                        echo json_encode($comment, JSON_UNESCAPED_UNICODE);
                        exit;
                    } else {
                        echo "ERROR"; exit;
                    }
                } else {
                    $p["comments"][]=$comment;
                    saveData($data_file,$data);
                    header('Content-Type: application/json; charset=utf-8');
                    echo json_encode($comment, JSON_UNESCAPED_UNICODE);
                    exit;
                }
            }
        }
    }

    if($_POST['api']=="edit_post"){
        $post_id = $_POST['post_id'] ?? '';
        $text = $sanitizeText($_POST['text'] ?? '');
        if(!preg_match('/^post_[a-z0-9]+$/i', $post_id) || trim($text)===''){ echo "ERROR"; exit; }
        foreach($data['posts'] as &$p){
            if($p['id']==$post_id && ( $p['user']==$_SESSION['user_name'] || ( ($p['ip'] ?? '') === getClientIP() ) )){
                $p['text'] = $text;
                $media = handleUploadedMedia('media');
                if($media) $p['media'] = $media;
                saveData($data_file,$data);
                echo "OK"; exit;
            }
        }
        echo "ERROR"; exit;
    }

    if($_POST['api']=="edit_comment"){
        $post_id = $_POST['post_id'] ?? '';
        $time = $_POST['time'] ?? '';
        $text = $sanitizeText($_POST['text'] ?? '');
        if(!preg_match('/^post_[a-z0-9]+$/i', $post_id) || !is_numeric($time) || trim($text)===''){ echo "ERROR"; exit; }
        foreach($data['posts'] as &$p){
            if($p['id']==$post_id){
                $c = &findCommentByTimeRecursive($p['comments'], $time);
                if($c !== null && ( $c['user']==$_SESSION['user_name'] || ( ($c['ip'] ?? '') === getClientIP() ) )){
                    $c['text'] = $text;
                    $media = handleUploadedMedia('media');
                    if($media) $c['media'] = $media;
                    saveData($data_file,$data);
                    echo "OK"; exit;
                }
            }
        }
        echo "ERROR"; exit;
    }
}

if(isset($_GET['fetch_posts'])){
    foreach(array_reverse($data['posts']) as $post){
        $postAvatar = getAvatarUrlForUser($post['user']);
        $reactCounts = [];
        foreach(["like","love","wow","angry"] as $rt){
            $n = count($post['reactions'][$rt]??[]);
            if($n > 0) $reactCounts[$rt] = $n;
        }
        $totalReacts = array_sum($reactCounts);
        $totalComments = count($post['comments'] ?? []);
        ?>
        <div class="fb-post" id="post_<?= $post['id'] ?>">
            <div class="fb-post-header">
                <div class="fb-post-avatar">
                    <?php if($postAvatar): ?>
                        <img src="<?= htmlspecialchars($postAvatar) ?>" alt="" class="fb-avatar-img">
                    <?php else: ?>
                        <div class="fb-avatar-fallback"><?= htmlspecialchars(mb_substr($post['user'],0,1)) ?></div>
                    <?php endif; ?>
                </div>
                <div class="fb-post-meta">
                    <div class="fb-post-author"><?= htmlspecialchars($post['user']) ?></div>
                    <div class="fb-post-time">
                        <?= timeAgo((int)$post['time']) ?>
                        <span class="fb-post-privacy">🌐</span>
                    </div>
                </div>
                <?php if($post['user']==$_SESSION['user_name'] || ( ($post['ip'] ?? '') === getClientIP() )): ?>
                <div class="fb-post-menu">
                    <button class="fb-post-menu-btn" onclick="togglePostMenu('<?= $post['id'] ?>')">⋯</button>
                    <div class="fb-post-menu-dropdown" id="post_menu_<?= $post['id'] ?>">
                        <div class="fb-menu-item" onclick="editPost('<?= $post['id'] ?>'); togglePostMenu('<?= $post['id'] ?>')">
                            <span class="fb-menu-icon">✏️</span> แก้ไขโพสต์
                        </div>
                        <div class="fb-menu-item fb-menu-danger" onclick="deletePost('<?= $post['id'] ?>'); togglePostMenu('<?= $post['id'] ?>')">
                            <span class="fb-menu-icon">🗑️</span> ลบโพสต์
                        </div>
                    </div>
                </div>
                <?php endif; ?>
            </div>
            <div class="fb-post-content">
                <p class="fb-post-text"><?= nl2br(htmlspecialchars($post['text'])) ?></p>
                <?php if(!empty($post['media']) && !empty($post['media']['path'])):
                    $m = $post['media'];
                    $mpath = htmlspecialchars($m['path']);
                    if($m['kind'] === 'video'): ?>
                        <div class="fb-post-media"><video controls><source src="<?= $mpath ?>" type="<?= htmlspecialchars($m['mime']) ?>"></video></div>
                    <?php else: ?>
                        <div class="fb-post-media"><img src="<?= $mpath ?>" alt="media"></div>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
            <div class="fb-post-stats">
                <?php if($totalReacts > 0): ?>
                <div class="fb-stats-reacts">
                    <?php if(!empty($reactCounts['like'])): ?><span class="fb-react-icon">👍</span><?php endif; ?>
                    <?php if(!empty($reactCounts['love'])): ?><span class="fb-react-icon">❤️</span><?php endif; ?>
                    <?php if(!empty($reactCounts['wow'])): ?><span class="fb-react-icon">😮</span><?php endif; ?>
                    <?php if(!empty($reactCounts['angry'])): ?><span class="fb-react-icon">😡</span><?php endif; ?>
                    <span class="fb-stats-count"><?= $totalReacts ?></span>
                </div>
                <?php endif; ?>
                <?php if($totalComments > 0): ?>
                <div class="fb-stats-comments" onclick="toggleAllComments('<?= $post['id'] ?>')">
                    <?= $totalComments ?> ความคิดเห็น
                </div>
                <?php endif; ?>
            </div>
            <div class="fb-post-actions">
                <button class="fb-action-btn" id="react_btn_<?= $post['id'] ?>" onclick="showReactPicker('<?= $post['id'] ?>')" onmouseenter="showReactPicker('<?= $post['id'] ?>')">
                    <?php
                    $myReaction = null;
                    foreach(["like","love","wow","angry"] as $rt){
                        if(in_array($_SESSION['user_name'], $post['reactions'][$rt]??[])){ $myReaction = $rt; break; }
                    }
                    if($myReaction === 'like'): ?>
                        <span class="fb-react-active">👍</span> <span class="fb-react-text" style="color:#1877f2">ถูกใจ</span>
                    <?php elseif($myReaction === 'love'): ?>
                        <span class="fb-react-active">❤️</span> <span class="fb-react-text" style="color:#f33e58">ถูกใจ</span>
                    <?php elseif($myReaction === 'wow'): ?>
                        <span class="fb-react-active">😮</span> <span class="fb-react-text" style="color:#f7b928">ถูกใจ</span>
                    <?php elseif($myReaction === 'angry'): ?>
                        <span class="fb-react-active">😡</span> <span class="fb-react-text" style="color:#e9710f">ถูกใจ</span>
                    <?php else: ?>
                        <svg class="fb-action-icon" viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>
                        <span>ถูกใจ</span>
                    <?php endif; ?>
                </button>
                <div class="fb-react-picker" id="react_picker_<?= $post['id'] ?>" onmouseleave="hideReactPicker('<?= $post['id'] ?>')">
                    <?php foreach(["like"=>"👍","love"=>"❤️","wow"=>"😮","angry"=>"😡"] as $type=>$emoji): ?>
                        <span class="fb-react-option" onclick="react('<?= $post['id'] ?>','<?= $type ?>'); hideReactPicker('<?= $post['id'] ?>')" title="<?= $type ?>"><?= $emoji ?></span>
                    <?php endforeach; ?>
                </div>
                <button class="fb-action-btn" onclick="focusComment('<?= $post['id'] ?>')">
                    <svg class="fb-action-icon" viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2z"/></svg>
                    <span>แสดงความคิดเห็น</span>
                </button>
                <button class="fb-action-btn">
                    <svg class="fb-action-icon" viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M18 16.08c-.76 0-1.44.3-1.96.77L8.91 12.7c.05-.23.09-.46.09-.7s-.04-.47-.09-.7l7.05-4.11c.54.5 1.25.81 2.04.81 1.66 0 3-1.34 3-3s-1.34-3-3-3-3 1.34-3 3c0 .24.04.47.09.7L8.04 9.81C7.5 9.31 6.79 9 6 9c-1.66 0-3 1.34-3 3s1.34 3 3 3c.79 0 1.5-.31 2.04-.81l7.12 4.16c-.05.21-.08.43-.08.65 0 1.61 1.31 2.92 2.92 2.92s2.92-1.31 2.92-2.92-1.31-2.92-2.92-2.92z"/></svg>
                    <span>แชร์</span>
                </button>
            </div>
            <div class="fb-comments-section">
                <?php if($totalComments > 0): ?>
                <div class="fb-comments-toggle">
                    <button id="toggle_comments_btn_<?= $post['id'] ?>" class="fb-toggle-btn"
                            data-count="<?= $totalComments ?>"
                            onclick="toggleAllComments('<?= $post['id'] ?>')">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 8l-6 6 1.41 1.41L12 10.83l4.59 4.58L18 14z"/></svg>
                        ดูความคิดเห็นทั้งหมด <?= $totalComments ?> รายการ
                    </button>
                </div>
                <?php endif; ?>
                <div id="comments_container_<?= $post['id'] ?>" class="comments-collapsed" style="display:none;">
                    <?php
                    $topComments = $post['comments'] ?? [];
                    $totalTop = count($topComments);
                    if ($totalTop > 10) {
                        $maxShow = 10;
                        $hiddenCount = $totalTop - $maxShow;
                        ?>
                        <div class="fb-view-more">
                            <span class="fb-view-more-btn" id="post_replies_toggle_<?= $post['id'] ?>" onclick="revealPrevTopComments('<?= $post['id'] ?>')">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 8l-6 6 1.41 1.41L12 10.83l4.59 4.58L18 14z"/></svg>
                                ดูความคิดเห็นเพิ่มเติมอีก <?= $hiddenCount ?> รายการ
                            </span>
                        </div>
                        <?php
                        echo '<div id="post_replies_hidden_'.$post['id'].'" class="replies-hidden">';
                        $earlier = array_slice($topComments, 0, $hiddenCount, true);
                        renderComments($earlier, $post['id'], 0);
                        echo '</div>';
                        $visible = array_slice($topComments, -$maxShow, $maxShow, true);
                        renderComments($visible, $post['id'], 0);
                    } else {
                        renderComments($topComments, $post['id'], 0);
                    }
                    ?>
                </div>
                <div class="fb-comment-input-row">
                    <?php $myAvatar = getAvatarUrlForUser($_SESSION['user_name']); ?>
                    <div class="fb-comment-avatar">
                        <?php if($myAvatar): ?>
                            <img src="<?= htmlspecialchars($myAvatar) ?>" alt="" class="fb-avatar-img" style="width:32px;height:32px">
                        <?php else: ?>
                            <div class="fb-avatar-fallback" style="width:32px;height:32px;font-size:13px"><?= htmlspecialchars(mb_substr($_SESSION['user_name'],0,1)) ?></div>
                        <?php endif; ?>
                    </div>
                    <div class="fb-comment-input-wrap">
                        <input type="text" id="comment_<?= $post['id'] ?>" class="fb-comment-input" placeholder="เขียนความคิดเห็น..." onkeydown="if(event.key==='Enter')addComment('<?= $post['id'] ?>')">
                        <div class="fb-comment-input-actions">
                            <button type="button" class="fb-input-btn" onclick="document.getElementById('comment_media_<?= $post['id'] ?>').click()" title="แนบรูปภาพ/วิดีโอ">📷</button>
                            <button type="button" class="fb-input-btn" onclick="showEmojiPickerFor(document.getElementById('comment_<?= $post['id'] ?>'), this)" title="อีโมจิ">😊</button>
                            <input type="file" id="comment_media_<?= $post['id'] ?>" accept="image/*,video/*" style="display:none">
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }
    exit;
}
?>
<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MiniSocial</title>
<link href="https://fonts.googleapis.com/css2?family=Prompt:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Prompt',system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;background:#f0f2f5;color:#050505;min-height:100vh;-webkit-font-smoothing:antialiased}
.fb-navbar{position:fixed;top:0;left:0;right:0;height:56px;background:#ffffff;box-shadow:0 1px 3px rgba(0,0,0,0.08);display:flex;align-items:center;padding:0 16px;z-index:1000}
.fb-nav-left{display:flex;align-items:center;gap:8px;flex:0 0 auto}
.fb-logo{width:40px;height:40px;background:linear-gradient(135deg,#1877f2,#0d65d9);border-radius:50%;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800;font-size:22px;text-decoration:none;font-family:'Helvetica Neue',Arial,sans-serif}
.fb-search{display:flex;align-items:center;background:#f0f2f5;border-radius:20px;padding:9px 12px;gap:8px;width:240px}
.fb-search svg{color:#65676b;flex-shrink:0}
.fb-search input{border:none;background:transparent;outline:none;font-size:15px;font-family:inherit;width:100%;color:#050505}
.fb-search input::placeholder{color:#65676b}
.fb-nav-center{display:flex;align-items:center;gap:4px;flex:1;justify-content:center}
.fb-nav-tab{display:flex;align-items:center;justify-content:center;height:48px;padding:0 32px;border-radius:8px;cursor:pointer;color:#65676b;transition:all .15s;position:relative}
.fb-nav-tab:hover{background:#f0f2f5}
.fb-nav-tab.active{color:#1877f2}
.fb-nav-tab.active::after{content:'';position:absolute;bottom:0;left:0;right:0;height:3px;background:#1877f2;border-radius:3px 3px 0 0}
.fb-nav-tab svg{width:24px;height:24px;fill:currentColor}
.fb-nav-right{display:flex;align-items:center;gap:8px;flex:0 0 auto;justify-content:flex-end}
.fb-nav-btn{width:40px;height:40px;background:#e4e6eb;border-radius:50%;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:background .15s;border:none;font-size:18px}
.fb-nav-btn:hover{background:#d8dadf}
.fb-nav-avatar{width:40px;height:40px;border-radius:50%;object-fit:cover;cursor:pointer}
.fb-nav-avatar-fallback{width:40px;height:40px;border-radius:50%;background:#e4e6eb;display:flex;align-items:center;justify-content:center;font-weight:600;color:#050505;font-size:15px;cursor:pointer}
.fb-main{max-width:680px;margin:0 auto;padding:72px 16px 40px}
.fb-create-post{background:#fff;border-radius:8px;box-shadow:0 1px 2px rgba(0,0,0,0.1);padding:12px 16px 10px;margin-bottom:16px}
.fb-create-post-top{display:flex;align-items:center;gap:8px;padding-bottom:8px;border-bottom:1px solid #e4e6eb;margin-bottom:8px}
.fb-create-post-avatar{width:40px;height:40px;border-radius:50%;object-fit:cover}
.fb-create-post-avatar-fallback{width:40px;height:40px;border-radius:50%;background:#e4e6eb;display:flex;align-items:center;justify-content:center;font-weight:600;color:#050505;font-size:15px}
.fb-create-post-input{flex:1;background:#f0f2f5;border:none;border-radius:20px;padding:10px 16px;font-size:17px;font-family:inherit;color:#050505;cursor:pointer;transition:background .15s;text-align:left;width:100%;resize:none}
.fb-create-post-input:hover{background:#e4e6eb}
.fb-create-post-input::placeholder{color:#65676b}
.fb-create-post-actions{display:flex;align-items:center;gap:4px;margin-top:8px}
.fb-create-option{flex:1;display:flex;align-items:center;justify-content:center;gap:8px;padding:8px;border-radius:8px;cursor:pointer;transition:background .15s;font-size:15px;font-weight:600;color:#65676b;border:none;background:transparent;font-family:inherit}
.fb-create-option:hover{background:#f0f2f5}
.fb-create-option svg{width:24px;height:24px}
.fb-post{background:#fff;border-radius:8px;box-shadow:0 1px 2px rgba(0,0,0,0.1);margin-bottom:16px;overflow:hidden}
.fb-post-header{display:flex;align-items:center;padding:12px 16px 0;gap:8px;position:relative}
.fb-post-avatar{width:40px;height:40px;border-radius:50%;object-fit:cover;flex-shrink:0}
.fb-post-meta{flex:1}
.fb-post-author{font-size:15px;font-weight:600;color:#050505;text-decoration:none}
.fb-post-author:hover{text-decoration:underline}
.fb-post-time{font-size:13px;color:#65676b;display:flex;align-items:center;gap:4px}
.fb-post-privacy{font-size:11px}
.fb-post-menu{margin-left:auto;position:relative}
.fb-post-menu-btn{width:36px;height:36px;border-radius:50%;border:none;background:transparent;cursor:pointer;font-size:20px;color:#65676b;display:flex;align-items:center;justify-content:center;transition:background .15s}
.fb-post-menu-btn:hover{background:#f0f2f5}
.fb-post-menu-dropdown{display:none;position:absolute;right:0;top:40px;background:#fff;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,0.15);padding:8px 0;min-width:200px;z-index:100}
.fb-post-menu-dropdown.show{display:block}
.fb-menu-item{display:flex;align-items:center;gap:12px;padding:8px 16px;cursor:pointer;font-size:15px;color:#050505;transition:background .1s}
.fb-menu-item:hover{background:#f0f2f5}
.fb-menu-icon{font-size:18px}
.fb-menu-danger{color:#e41e3f}
.fb-post-content{padding:8px 16px 0}
.fb-post-text{font-size:15px;line-height:1.5;color:#050505;white-space:pre-wrap;word-wrap:break-word}
.fb-post-media{margin:8px -16px 0}
.fb-post-media img,.fb-post-media video{width:100%;max-height:500px;object-fit:cover;display:block}
.fb-post-stats{display:flex;align-items:center;justify-content:space-between;padding:8px 16px}
.fb-stats-reacts{display:flex;align-items:center;gap:4px}
.fb-react-icon{font-size:16px}
.fb-stats-count{font-size:15px;color:#65676b;margin-left:2px}
.fb-stats-comments{font-size:15px;color:#65676b;cursor:pointer}
.fb-stats-comments:hover{text-decoration:underline}
.fb-post-actions{display:flex;align-items:center;margin:0 16px;border-top:1px solid #e4e6eb;border-bottom:1px solid #e4e6eb;padding:4px 0;position:relative}
.fb-action-btn{flex:1;display:flex;align-items:center;justify-content:center;gap:6px;padding:8px;border-radius:6px;cursor:pointer;border:none;background:transparent;font-size:15px;font-weight:600;color:#65676b;font-family:inherit;transition:background .15s}
.fb-action-btn:hover{background:#f0f2f5}
.fb-action-icon{width:20px;height:20px;fill:currentColor}
.fb-react-active{font-size:18px}
.fb-react-text{font-size:15px;font-weight:600}
.fb-react-picker{display:none;position:absolute;bottom:100%;left:0;background:#fff;border-radius:24px;box-shadow:0 2px 8px rgba(0,0,0,0.15);padding:4px 8px;gap:4px;z-index:50}
.fb-react-picker.show{display:flex}
.fb-react-option{width:40px;height:40px;display:flex;align-items:center;justify-content:center;font-size:28px;cursor:pointer;border-radius:50%;transition:transform .15s}
.fb-react-option:hover{transform:scale(1.3)}
.fb-comments-section{padding:4px 16px 12px}
.fb-comments-toggle{margin-bottom:8px}
.fb-toggle-btn{display:flex;align-items:center;gap:6px;background:none;border:none;cursor:pointer;font-size:15px;font-weight:600;color:#65676b;font-family:inherit;padding:4px 0}
.fb-toggle-btn:hover{text-decoration:underline}
.fb-toggle-btn svg{transition:transform .2s}
.fb-toggle-btn.open svg{transform:rotate(180deg)}
.fb-comment-row{display:flex;gap:6px;margin-bottom:8px}
.fb-comment-avatar{flex-shrink:0}
.fb-avatar-img{width:32px;height:32px;border-radius:50%;object-fit:cover}
.fb-avatar-fallback{width:32px;height:32px;border-radius:50%;background:#e4e6eb;display:flex;align-items:center;justify-content:center;font-weight:600;color:#050505;font-size:13px}
.fb-comment-body{flex:1;min-width:0}
.fb-comment-bubble{display:inline-block;background:#f0f2f5;border-radius:16px;padding:8px 12px;max-width:100%}
.fb-comment-author{font-size:13px;font-weight:600;color:#050505;margin-bottom:2px}
.fb-comment-text{font-size:15px;color:#050505;line-height:1.4;word-wrap:break-word}
.fb-comment-media{margin-top:6px}
.fb-comment-media img,.fb-comment-media video{max-width:100%;border-radius:8px}
.fb-comment-reacts{display:flex;gap:4px;margin:2px 0 0 12px}
.fb-react-pill{background:#fff;border-radius:10px;padding:1px 6px;font-size:12px;box-shadow:0 1px 2px rgba(0,0,0,0.1);display:flex;align-items:center;gap:2px}
.fb-comment-actions{display:flex;align-items:center;gap:12px;margin:2px 0 0 12px}
.fb-comment-time{font-size:12px;color:#65676b}
.fb-comment-action{font-size:12px;font-weight:600;color:#65676b;cursor:pointer}
.fb-comment-action:hover{text-decoration:underline}
.fb-action-danger:hover{color:#e41e3f}
.fb-view-more{margin:8px 0}
.fb-view-more-btn{display:flex;align-items:center;gap:6px;font-size:15px;font-weight:600;color:#65676b;cursor:pointer;background:none;border:none;font-family:inherit;padding:4px 0}
.fb-view-more-btn:hover{text-decoration:underline}
.fb-comment-input-row{display:flex;align-items:center;gap:8px;margin-top:8px}
.fb-comment-input-wrap{flex:1;display:flex;align-items:center;background:#f0f2f5;border-radius:20px;padding:4px 4px 4px 12px}
.fb-comment-input{flex:1;border:none;background:transparent;outline:none;font-size:15px;font-family:inherit;color:#050505;padding:6px 0}
.fb-comment-input::placeholder{color:#65676b}
.fb-comment-input-actions{display:flex;align-items:center;gap:2px}
.fb-input-btn{width:32px;height:32px;border-radius:50%;border:none;background:transparent;cursor:pointer;font-size:16px;display:flex;align-items:center;justify-content:center;transition:background .15s}
.fb-input-btn:hover{background:#e4e6eb}
.fb-read-more{color:#65676b;font-size:14px;font-weight:600;cursor:pointer;margin-left:4px}
.fb-read-more:hover{text-decoration:underline}
#edit_modal_overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:2000;align-items:center;justify-content:center}
#edit_modal{background:#fff;border-radius:12px;width:95%;max-width:500px;box-shadow:0 4px 24px rgba(0,0,0,0.15);overflow:hidden}
.fb-modal-header{display:flex;align-items:center;justify-content:center;padding:16px;border-bottom:1px solid #e4e6eb;position:relative}
.fb-modal-header h3{font-size:20px;font-weight:700;color:#050505}
.fb-modal-close{position:absolute;right:12px;width:36px;height:36px;border-radius:50%;border:none;background:#e4e6eb;cursor:pointer;font-size:18px;display:flex;align-items:center;justify-content:center;transition:background .15s}
.fb-modal-close:hover{background:#d8dadf}
.fb-modal-body{padding:16px}
.fb-modal-body textarea{width:100%;min-height:120px;border:1px solid #dddfe2;border-radius:8px;padding:12px;font-size:15px;font-family:inherit;resize:vertical;outline:none;transition:border-color .2s}
.fb-modal-body textarea:focus{border-color:#1877f2}
.fb-modal-footer{display:flex;gap:8px;justify-content:flex-end;padding:12px 16px;border-top:1px solid #e4e6eb}
.fb-modal-btn{padding:8px 16px;border-radius:6px;font-size:15px;font-weight:600;font-family:inherit;cursor:pointer;border:none;transition:background .15s}
.fb-modal-btn-cancel{background:#e4e6eb;color:#050505}
.fb-modal-btn-cancel:hover{background:#d8dadf}
.fb-modal-btn-primary{background:#1877f2;color:#fff}
.fb-modal-btn-primary:hover{background:#166fe5}
#reply_modal_overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:2000;align-items:center;justify-content:center}
#reply_modal{background:#fff;border-radius:12px;width:95%;max-width:500px;box-shadow:0 4px 24px rgba(0,0,0,0.15);overflow:hidden}
#emoji_picker{display:none;position:fixed;z-index:3000;background:#fff;border-radius:12px;box-shadow:0 4px 16px rgba(0,0,0,0.12);padding:12px;max-width:320px;max-height:300px;overflow:auto}
#emoji_grid{display:grid;grid-template-columns:repeat(8,1fr);gap:4px}
#emoji_grid button{width:32px;height:32px;border:none;background:transparent;font-size:20px;cursor:pointer;border-radius:6px;transition:background .1s}
#emoji_grid button:hover{background:#f0f2f5}
#status-toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);z-index:5000;display:none;background:#313131;color:#fff;padding:12px 20px;border-radius:8px;font-size:14px;font-weight:500;box-shadow:0 4px 12px rgba(0,0,0,0.2);animation:toastIn .3s ease}
@keyframes toastIn{from{opacity:0;transform:translateX(-50%) translateY(10px)}to{opacity:1;transform:translateX(-50%) translateY(0)}}
.scroll-top-btn{position:fixed;right:24px;bottom:24px;width:44px;height:44px;border-radius:50%;background:#fff;border:none;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,0.15);font-size:20px;color:#050505;display:none;align-items:center;justify-content:center;z-index:1000;transition:all .15s}
.scroll-top-btn:hover{background:#f0f2f5;transform:translateY(-2px)}
.scroll-top-btn.visible{display:flex}
.replies-hidden{display:none;margin-top:6px}
.comments-collapsed{display:none}
@media(max-width:720px){.fb-search{display:none}.fb-nav-tab{padding:0 16px}.fb-main{padding:64px 8px 20px}}
@media(max-width:480px){.fb-nav-center{display:none}.fb-create-option span{display:none}.fb-action-btn span{display:none}.fb-action-btn{flex:0 0 auto;padding:8px 12px}}
</style>
</head>
<body>
<header class="fb-navbar">
  <div class="fb-nav-left">
    <a href="#" class="fb-logo">M</a>
    <div class="fb-search">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M15.5 14h-.79l-.28-.27A6.471 6.471 0 0016 9.5 6.5 6.5 0 109.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
      <input type="text" placeholder="ค้นหาใน MiniSocial">
    </div>
  </div>
  <nav class="fb-nav-center">
    <div class="fb-nav-tab active"><svg viewBox="0 0 24 24"><path d="M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z"/></svg></div>
    <div class="fb-nav-tab"><svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg></div>
    <div class="fb-nav-tab"><svg viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2z"/></svg></div>
  </nav>
  <div class="fb-nav-right">
    <button class="fb-nav-btn" title="เมนู">☰</button>
    <button class="fb-nav-btn" title="แชท">💬</button>
    <button class="fb-nav-btn" title="การแจ้งเตือน">🔔</button>
    <?php $navAvatar = getAvatarUrlForUser($_SESSION['user_name']);
    if($navAvatar): ?>
      <img src="<?= htmlspecialchars($navAvatar) ?>" alt="" class="fb-nav-avatar">
    <?php else: ?>
      <div class="fb-nav-avatar-fallback"><?= htmlspecialchars(mb_substr($_SESSION['user_name'],0,1)) ?></div>
    <?php endif; ?>
  </div>
</header>

<main class="fb-main">
  <div class="fb-create-post">
    <div class="fb-create-post-top">
      <?php $myAvatar = getAvatarUrlForUser($_SESSION['user_name']); ?>
      <?php if($myAvatar): ?>
        <img src="<?= htmlspecialchars($myAvatar) ?>" alt="" class="fb-create-post-avatar">
      <?php else: ?>
        <div class="fb-create-post-avatar-fallback"><?= htmlspecialchars(mb_substr($_SESSION['user_name'],0,1)) ?></div>
      <?php endif; ?>
      <button class="fb-create-post-input" onclick="openCreateModal()"><?= htmlspecialchars($_SESSION['user_name']) ?>, คุณกำลังคิดอะไรอยู่?</button>
    </div>
    <div class="fb-create-post-actions">
      <button class="fb-create-option" onclick="openCreateModal()">
        <svg viewBox="0 0 24 24" fill="#f3425f"><path d="M21 19V5c0-1.1-.9-2-2-2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2zM8.5 13.5l2.5 3.01L14.5 12l4.5 6H5l3.5-4.5z"/></svg>
        <span>รูปภาพ/วิดีโอ</span>
      </button>
      <button class="fb-create-option" onclick="openCreateModal()">
        <svg viewBox="0 0 24 24" fill="#45bd62"><path d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm3.5-9c.83 0 1.5-.67 1.5-1.5S16.33 8 15.5 8 14 8.67 14 9.5s.67 1.5 1.5 1.5zm-7 0c.83 0 1.5-.67 1.5-1.5S9.33 8 8.5 8 7 8.67 7 9.5 7.67 11 8.5 11zm3.5 6.5c2.33 0 4.31-1.46 5.11-3.5H6.89c.8 2.04 2.78 3.5 5.11 3.5z"/></svg>
        <span>ความรู้สึก</span>
      </button>
      <button class="fb-create-option" onclick="openCreateModal()">
        <svg viewBox="0 0 24 24" fill="#f7b928"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>
        <span>ตำแหน่ง</span>
      </button>
    </div>
  </div>
  <div id="post_area"></div>
</main>

<div id="create_modal_overlay" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:2000;align-items:center;justify-content:center;">
  <div style="background:#fff;border-radius:12px;width:95%;max-width:500px;box-shadow:0 4px 24px rgba(0,0,0,0.15);overflow:hidden;">
    <div class="fb-modal-header">
      <h3>สร้างโพสต์</h3>
      <button class="fb-modal-close" onclick="hideCreateModal()">✕</button>
    </div>
    <div class="fb-modal-body">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;">
        <?php if($myAvatar): ?>
          <img src="<?= htmlspecialchars($myAvatar) ?>" alt="" style="width:40px;height:40px;border-radius:50%;object-fit:cover;">
        <?php else: ?>
          <div style="width:40px;height:40px;border-radius:50%;background:#e4e6eb;display:flex;align-items:center;justify-content:center;font-weight:600;"><?= htmlspecialchars(mb_substr($_SESSION['user_name'],0,1)) ?></div>
        <?php endif; ?>
        <div>
          <div style="font-weight:600;font-size:15px;"><?= htmlspecialchars($_SESSION['user_name']) ?></div>
          <div style="font-size:12px;color:#65676b;">สาธารณะ 🌐</div>
        </div>
      </div>
      <textarea id="create_post_text" placeholder="<?= htmlspecialchars($_SESSION['user_name']) ?>, คุณกำลังคิดอะไรอยู่?" style="width:100%;min-height:150px;border:none;font-size:17px;font-family:inherit;resize:none;outline:none;" oninput="this.style.height='auto';this.style.height=Math.max(150,this.scrollHeight)+'px'"></textarea>
      <div id="create_media_preview" style="display:none;margin-top:8px;position:relative;">
        <img id="create_media_img" src="" style="max-width:100%;border-radius:8px;display:none;">
        <video id="create_media_vid" controls style="max-width:100%;border-radius:8px;display:none;"></video>
        <button onclick="clearCreateMedia()" style="position:absolute;top:8px;right:8px;width:28px;height:28px;border-radius:50%;border:none;background:rgba(0,0,0,0.5);color:#fff;cursor:pointer;font-size:14px;">✕</button>
      </div>
      <div style="display:flex;align-items:center;justify-content:space-between;border:1px solid #dddfe2;border-radius:8px;padding:12px;margin-top:12px;">
        <span style="font-weight:600;font-size:15px;">เพิ่มในโพสต์ของคุณ</span>
        <div style="display:flex;gap:4px;">
          <button type="button" onclick="document.getElementById('create_post_media').click()" style="width:36px;height:36px;border-radius:50%;border:none;background:transparent;cursor:pointer;font-size:20px;" title="รูปภาพ/วิดีโอ">🖼️</button>
          <button type="button" onclick="showEmojiPickerFor(document.getElementById('create_post_text'), this)" style="width:36px;height:36px;border-radius:50%;border:none;background:transparent;cursor:pointer;font-size:20px;" title="อีโมจิ">😊</button>
        </div>
      </div>
      <input type="file" id="create_post_media" accept="image/*,video/*" style="display:none">
    </div>
    <div class="fb-modal-footer" style="padding:12px 16px;">
      <button class="fb-modal-btn fb-modal-btn-primary" style="width:100%" onclick="addPost()">โพสต์</button>
    </div>
  </div>
</div>

<div id="edit_modal_overlay">
  <div id="edit_modal">
    <div class="fb-modal-header">
      <h3>แก้ไขโพสต์</h3>
      <button class="fb-modal-close" onclick="hideEditModal()">✕</button>
    </div>
    <div class="fb-modal-body">
      <textarea id="edit_modal_text" placeholder="คุณกำลังคิดอะไรอยู่?"></textarea>
      <div style="display:flex;gap:8px;margin-top:12px;">
        <button type="button" onclick="showEmojiPickerFor(document.getElementById('edit_modal_text'), this)" class="fb-input-btn" style="width:36px;height:36px;border-radius:50%;border:none;background:#f0f2f5;cursor:pointer;font-size:18px;">😊</button>
        <input type="file" id="edit_modal_media" accept="image/*,video/*" style="display:none">
        <button type="button" onclick="document.getElementById('edit_modal_media').click()" class="fb-input-btn" style="width:36px;height:36px;border-radius:50%;border:none;background:#f0f2f5;cursor:pointer;font-size:18px;" title="เพิ่มรูปภาพ">📷</button>
      </div>
    </div>
    <div class="fb-modal-footer">
      <button class="fb-modal-btn fb-modal-btn-cancel" onclick="hideEditModal()">ยกเลิก</button>
      <button class="fb-modal-btn fb-modal-btn-primary" id="edit_modal_save">บันทึก</button>
    </div>
  </div>
</div>

<div id="reply_modal_overlay">
  <div id="reply_modal">
    <div class="fb-modal-header">
      <h3>ตอบคอมเมนต์</h3>
      <button class="fb-modal-close" onclick="hideReplyModal()">✕</button>
    </div>
    <div class="fb-modal-body">
      <textarea id="reply_modal_text" placeholder="เขียนคำตอบ..."></textarea>
      <div style="display:flex;gap:8px;margin-top:12px;">
        <button type="button" onclick="showEmojiPickerFor(document.getElementById('reply_modal_text'), this)" class="fb-input-btn" style="width:36px;height:36px;border-radius:50%;border:none;background:#f0f2f5;cursor:pointer;font-size:18px;">😊</button>
        <input type="file" id="reply_modal_media" accept="image/*,video/*" style="display:none">
        <button type="button" onclick="document.getElementById('reply_modal_media').click()" class="fb-input-btn" style="width:36px;height:36px;border-radius:50%;border:none;background:#f0f2f5;cursor:pointer;font-size:18px;" title="เพิ่มรูปภาพ">📷</button>
      </div>
    </div>
    <div class="fb-modal-footer">
      <button class="fb-modal-btn fb-modal-btn-cancel" onclick="hideReplyModal()">ยกเลิก</button>
      <button class="fb-modal-btn fb-modal-btn-primary" id="reply_modal_save" style="background:#42b72a;">ตอบ</button>
    </div>
  </div>
</div>

<div id="emoji_picker"><div id="emoji_grid"></div></div>
<div id="status-toast"><span id="toast_msg">เรียบร้อย</span></div>
<button id="scroll_top_btn" class="scroll-top-btn" title="เลื่อนขึ้นด้านบน">↑</button>

<script>
const CSRF_TOKEN = '<?= htmlspecialchars($_SESSION['csrf_token']) ?>';

function showToast(msg="เรียบร้อย"){
  const t=document.getElementById("status-toast");
  document.getElementById("toast_msg").textContent=msg;
  t.style.display="block";
  setTimeout(()=>{t.style.display="none"},2500);
}

function openCreateModal(){
  document.getElementById('create_modal_overlay').style.display='flex';
  setTimeout(()=>document.getElementById('create_post_text').focus(),100);
}
function hideCreateModal(){
  document.getElementById('create_modal_overlay').style.display='none';
  document.getElementById('create_post_text').value='';
  clearCreateMedia();
}
function clearCreateMedia(){
  const prev=document.getElementById('create_media_preview');
  const img=document.getElementById('create_media_img');
  const vid=document.getElementById('create_media_vid');
  prev.style.display='none';
  img.style.display='none';img.src='';
  vid.style.display='none';vid.src='';
  document.getElementById('create_post_media').value='';
}
document.getElementById('create_post_media').addEventListener('change',function(){
  const f=this.files&&this.files[0];
  if(!f)return;
  const prev=document.getElementById('create_media_preview');
  const img=document.getElementById('create_media_img');
  const vid=document.getElementById('create_media_vid');
  if(f.type.startsWith('image/')){
    const reader=new FileReader();
    reader.onload=function(e){img.src=e.target.result;img.style.display='block';vid.style.display='none';prev.style.display='block'};
    reader.readAsDataURL(f);
  }else if(f.type.startsWith('video/')){
    const url=URL.createObjectURL(f);
    vid.src=url;vid.style.display='block';img.style.display='none';prev.style.display='block';
  }
});

function addPost(){
  const text=document.getElementById('create_post_text').value;
  if(text.trim()==="")return;
  const fd=new FormData();
  fd.append('api','add_post');
  fd.append('text',text);
  fd.append('csrf_token',CSRF_TOKEN);
  const file=document.getElementById('create_post_media');
  if(file&&file.files&&file.files[0])fd.append('media',file.files[0]);
  fetch("<?=$_SERVER['PHP_SELF']?>",{method:"POST",body:fd})
    .then(res=>res.text())
    .then(res=>{
      if(res==="OK"){hideCreateModal();loadPosts();showToast("โพสต์สำเร็จ 🎉")}
    });
}

function editPost(postId){
  const el=document.querySelector(`#post_${postId} .fb-post-text`);
  const current=el?el.innerText.replace(/ /g,' ').trim():'';
  showEditModal('post',postId,null,current);
}

let _editContext=null;
function showEditModal(type,postId,time=null,currentText=''){
  _editContext={type,postId,time};
  const overlay=document.getElementById('edit_modal_overlay');
  const textarea=document.getElementById('edit_modal_text');
  const media=document.getElementById('edit_modal_media');
  textarea.value=currentText||'';
  if(media)media.value='';
  overlay.style.display='flex';
  setTimeout(()=>{textarea.focus();textarea.setSelectionRange(textarea.value.length,textarea.value.length)},50);
}
function hideEditModal(){
  _editContext=null;
  document.getElementById('edit_modal_overlay').style.display='none';
  document.getElementById('edit_modal_text').value='';
  document.getElementById('edit_modal_media').value='';
}
document.getElementById('edit_modal_save').addEventListener('click',function(){
  if(!_editContext)return;
  const text=(document.getElementById('edit_modal_text').value||'').trim();
  if(text===''){alert('ข้อความต้องไม่ว่าง');return}
  const fd=new FormData();
  const api=(_editContext.type==='post')?'edit_post':'edit_comment';
  fd.append('api',api);
  fd.append('text',text);
  fd.append('csrf_token',CSRF_TOKEN);
  fd.append('post_id',_editContext.postId);
  if(_editContext.type==='comment')fd.append('time',_editContext.time);
  const mediaEl=document.getElementById('edit_modal_media');
  if(mediaEl&&mediaEl.files&&mediaEl.files[0])fd.append('media',mediaEl.files[0]);
  fetch("<?=$_SERVER['PHP_SELF']?>",{method:'POST',body:fd})
    .then(res=>res.text())
    .then(res=>{
      if(res==='OK'){hideEditModal();loadPosts();showToast('แก้ไขเรียบร้อย ✏️')}
      else showToast('ไม่สามารถแก้ไขได้');
    }).catch(()=>showToast('ไม่สามารถแก้ไขได้'));
});

function deletePost(postId){
  if(!confirm("คุณแน่ใจว่าต้องการลบโพสต์นี้?"))return;
  fetch("<?=$_SERVER['PHP_SELF']?>",{
    method:"POST",
    headers:{"Content-Type":"application/x-www-form-urlencoded"},
    body:"api=delete_post&post_id="+encodeURIComponent(postId)+"&csrf_token="+encodeURIComponent(CSRF_TOKEN)
  }).then(res=>res.text())
    .then(res=>{if(res==="OK"){loadPosts();showToast("ลบโพสต์สำเร็จ 🗑️")}});
}

function deleteComment(postId,commentTime){
  if(!confirm("คุณแน่ใจว่าต้องการลบคอมเมนต์นี้?"))return;
  fetch("<?=$_SERVER['PHP_SELF']?>",{
    method:"POST",
    headers:{"Content-Type":"application/x-www-form-urlencoded"},
    body:"api=delete_comment&post_id="+encodeURIComponent(postId)+"&comment_time="+encodeURIComponent(commentTime)+"&csrf_token="+encodeURIComponent(CSRF_TOKEN)
  }).then(res=>res.text())
    .then(res=>{if(res==="OK"){loadPosts();showToast("ลบคอมเมนต์สำเร็จ 🗑️")}});
}

function showReactPicker(postId){
  document.querySelectorAll('.fb-react-picker').forEach(p=>{
    if(p.id!=='react_picker_'+postId)p.classList.remove('show');
  });
  const picker=document.getElementById('react_picker_'+postId);
  if(picker)picker.classList.add('show');
}
function hideReactPicker(postId){
  const picker=document.getElementById('react_picker_'+postId);
  if(picker)picker.classList.remove('show');
}

function react(postId,type){
  const open=_getOpenCommentsPosts();
  fetch("<?=$_SERVER['PHP_SELF']?>",{
    method:"POST",
    headers:{"Content-Type":"application/x-www-form-urlencoded"},
    body:"api=reaction&post_id="+encodeURIComponent(postId)+"&type="+encodeURIComponent(type)+"&csrf_token="+encodeURIComponent(CSRF_TOKEN)
  }).then(res=>res.text())
    .then(res=>{if(res==="OK")loadPosts(open)});
}

function reactComment(postId,commentTime,type){
  const open=_getOpenCommentsPosts();
  fetch("<?=$_SERVER['PHP_SELF']?>",{
    method:"POST",
    headers:{"Content-Type":"application/x-www-form-urlencoded"},
    body:"api=reaction_comment&post_id="+encodeURIComponent(postId)+"&comment_time="+encodeURIComponent(commentTime)+"&type="+encodeURIComponent(type)+"&csrf_token="+encodeURIComponent(CSRF_TOKEN)
  }).then(res=>res.text())
    .then(res=>{if(res==="OK")loadPosts(open)});
}

function focusComment(postId){
  const input=document.getElementById('comment_'+postId);
  if(input){
    input.scrollIntoView({behavior:'smooth',block:'center'});
    setTimeout(()=>input.focus(),500);
  }
}

function addComment(postId){
  let input=document.getElementById("comment_"+postId);
  if(!input)return;
  let text=input.value;
  const fileInput=document.getElementById('comment_media_'+postId);
  const hasFile=fileInput&&fileInput.files&&fileInput.files[0];
  if(text.trim()===""&&!hasFile)return;
  const fd=new FormData();
  fd.append('api','comment');
  fd.append('post_id',postId);
  fd.append('text',text);
  fd.append('csrf_token',CSRF_TOKEN);
  if(hasFile)fd.append('media',fileInput.files[0]);
  fetch("<?=$_SERVER['PHP_SELF']?>",{method:"POST",body:fd})
    .then(res=>res.json().catch(()=>null))
    .then(comment=>{
      loadPosts().then(()=>{
        showComments(postId);
        if(input)input.value="";
        if(fileInput)fileInput.value="";
        showToast("คอมเมนต์สำเร็จ 💬");
      });
    });
}

function loadPosts(openPosts=[]){
  return fetch("<?=$_SERVER['PHP_SELF']?>?fetch_posts=1")
    .then(res=>res.text())
    .then(html=>{
      document.getElementById("post_area").innerHTML=html;
      try{updateScrollTopVisibility()}catch(e){}
      if(Array.isArray(openPosts)&&openPosts.length){
        try{openPosts.forEach(pid=>{showComments(pid)})}catch(e){}
      }
    });
}

window.onload=loadPosts;

function editComment(postId,commentTime){
  const el=document.querySelector(`#comment_${postId}_${commentTime} .fb-comment-text`);
  const current=el?el.innerText.replace(/ /g,' ').trim():'';
  showEditModal('comment',postId,commentTime,current);
}

function replyComment(postId,parentTime){
  showReplyModal(postId,parentTime);
}

let _replyContext=null;
function showReplyModal(postId,parentTime,prefill=''){
  _replyContext={postId:postId,parentTime:parentTime};
  const overlay=document.getElementById('reply_modal_overlay');
  const textarea=document.getElementById('reply_modal_text');
  const media=document.getElementById('reply_modal_media');
  if(textarea)textarea.value=prefill||'';
  if(media)media.value='';
  if(overlay)overlay.style.display='flex';
  setTimeout(()=>{try{textarea.focus();textarea.setSelectionRange(textarea.value.length,textarea.value.length)}catch(e){}},50);
}
function hideReplyModal(){
  _replyContext=null;
  const overlay=document.getElementById('reply_modal_overlay');
  if(overlay)overlay.style.display='none';
  const textarea=document.getElementById('reply_modal_text');
  if(textarea)textarea.value='';
  const media=document.getElementById('reply_modal_media');
  if(media)media.value='';
}

document.getElementById('reply_modal_save').addEventListener('click',function(){
  if(!_replyContext)return;
  const text=(document.getElementById('reply_modal_text').value||'').trim();
  const mediaEl=document.getElementById('reply_modal_media');
  const hasFile=mediaEl&&mediaEl.files&&mediaEl.files[0];
  if(text===''&&!hasFile){alert('กรุณาใส่ข้อความหรือแนบไฟล์');return}
  if(hasFile&&mediaEl.files[0].size>8*1024*1024){alert('ขนาดไฟล์เกิน 8MB');return}
  const fd=new FormData();
  fd.append('api','comment');
  fd.append('post_id',_replyContext.postId);
  fd.append('parent_time',_replyContext.parentTime);
  fd.append('text',text);
  fd.append('csrf_token',CSRF_TOKEN);
  if(hasFile)fd.append('media',mediaEl.files[0]);
  fetch("<?=$_SERVER['PHP_SELF']?>",{method:'POST',body:fd})
    .then(res=>res.json().catch(()=>null))
    .then(resp=>{
      hideReplyModal();
      loadPosts().then(()=>{
        try{showComments(_replyContext.postId)}catch(e){}
        showToast("ตอบคอมเมนต์สำเร็จ 💬");
      });
    }).catch(()=>showToast('ไม่สามารถส่งคำตอบได้'));
});

function toggleLongText(postId,cid){
  const shortEl=document.getElementById(`short_text_${postId}_${cid}`);
  const fullEl=document.getElementById(`full_text_${postId}_${cid}`);
  const btn=document.getElementById(`read_more_btn_${postId}_${cid}`);
  if(!shortEl||!fullEl||!btn)return;
  if(fullEl.style.display==='none'||fullEl.style.display===''){
    fullEl.style.display='inline';
    shortEl.style.display='none';
    btn.textContent='ย่อข้อความ';
  }else{
    fullEl.style.display='none';
    shortEl.style.display='inline';
    btn.textContent='ดูเพิ่มเติม';
  }
}

function revealPrevTopComments(postId){
  const hid=document.getElementById(`post_replies_hidden_${postId}`);
  const btn=document.getElementById(`post_replies_toggle_${postId}`);
  if(!hid||!btn)return;
  const batch=5;
  let moved=0;
  const children=hid.querySelectorAll(`[id^="comment_${postId}_"]`);
  for(let i=children.length-1;i>=0&&moved<batch;i--){
    const node=children[i];
    hid.parentNode.insertBefore(node,hid);
    moved++;
  }
  const remaining=hid.querySelectorAll(`[id^="comment_${postId}_"]`).length;
  if(remaining===0){hid.remove();btn.style.display='none'}
  else btn.textContent=`ดูความคิดเห็นเพิ่มเติมอีก ${remaining} รายการ`;
}

function revealPrevReplies(postId,cid){
  const hidId=`replies_hidden_${postId}_${cid}`;
  const btnId=`replies_toggle_${postId}_${cid}`;
  const hid=document.getElementById(hidId);
  const btn=document.getElementById(btnId);
  if(!hid||!btn)return;
  const batch=3;
  let moved=0;
  const children=hid.querySelectorAll(`[id^="comment_${postId}_"]`);
  for(let i=children.length-1;i>=0&&moved<batch;i--){
    const node=children[i];
    hid.parentNode.insertBefore(node,hid);
    moved++;
  }
  const remaining=hid.querySelectorAll(`[id^="comment_${postId}_"]`).length;
  if(remaining===0){hid.remove();btn.style.display='none'}
  else btn.textContent=`ดูความคิดเห็นเพิ่มเติมอีก ${remaining} รายการ`;
}

function showComments(postId){
  const cont=document.getElementById(`comments_container_${postId}`);
  const btn=document.getElementById(`toggle_comments_btn_${postId}`);
  if(!cont)return;
  cont.style.display='';
  cont.classList.remove('comments-collapsed');
  if(btn){
    btn.textContent='ซ่อนความคิดเห็นทั้งหมด';
    btn.classList.add('open');
  }
  const hiddenEls=cont.querySelectorAll('.replies-hidden');
  hiddenEls.forEach(e=>e.style.display='block');
  const toggles=cont.querySelectorAll('.replies-toggle');
  toggles.forEach(t=>t.style.display='none');
}

function toggleAllComments(postId){
  const cont=document.getElementById(`comments_container_${postId}`);
  const btn=document.getElementById(`toggle_comments_btn_${postId}`);
  if(!cont||!btn)return;
  const isCollapsed=cont.classList.contains('comments-collapsed')||cont.style.display==='none';
  if(isCollapsed){
    cont.style.display='';
    cont.classList.remove('comments-collapsed');
    btn.textContent='ซ่อนความคิดเห็นทั้งหมด';
    btn.classList.add('open');
    const hiddenEls=cont.querySelectorAll('.replies-hidden');
    hiddenEls.forEach(e=>e.style.display='block');
    const toggles=cont.querySelectorAll('.replies-toggle');
    toggles.forEach(t=>t.style.display='none');
  }else{
    cont.style.display='none';
    cont.classList.add('comments-collapsed');
    btn.textContent=btn.dataset&&btn.dataset.count?`ดูความคิดเห็นทั้งหมด (${btn.dataset.count})`:'ดูความคิดเห็นทั้งหมด';
    btn.classList.remove('open');
    const hiddenEls=cont.querySelectorAll('.replies-hidden');
    hiddenEls.forEach(e=>e.style.display='none');
    const toggles=cont.querySelectorAll('.replies-toggle');
    toggles.forEach(t=>t.style.display='inline-block');
  }
}

function togglePostMenu(postId){
  const menu=document.getElementById(`post_menu_${postId}`);
  if(!menu)return;
  document.querySelectorAll('.fb-post-menu-dropdown').forEach(m=>{
    if(m.id!==`post_menu_${postId}`)m.classList.remove('show');
  });
  menu.classList.toggle('show');
}

function updateScrollTopVisibility(){
  const btn=document.getElementById('scroll_top_btn');
  if(!btn)return;
  const posts=document.querySelectorAll('#post_area .fb-post').length;
  const POST_THRESHOLD=8;
  const SCROLL_THRESHOLD=window.innerHeight*0.6;
  const shouldShow=posts>=POST_THRESHOLD||window.scrollY>SCROLL_THRESHOLD;
  if(shouldShow){btn.classList.add('visible');btn.setAttribute('aria-hidden','false')}
  else{btn.classList.remove('visible');btn.setAttribute('aria-hidden','true')}
}

let _scrollTimeout=null;
window.addEventListener('scroll',function(){
  if(_scrollTimeout)return;
  _scrollTimeout=setTimeout(function(){
    updateScrollTopVisibility();
    _scrollTimeout=null;
  },120);
});
window.addEventListener('resize',function(){updateScrollTopVisibility()});

document.getElementById('scroll_top_btn').addEventListener('click',function(e){
  e.preventDefault();
  window.scrollTo({top:0,behavior:'smooth'});
  this.classList.remove('visible');
  this.setAttribute('aria-hidden','true');
});

try{updateScrollTopVisibility()}catch(e){}

function _getOpenCommentsPosts(){
  const open=[];
  document.querySelectorAll('[id^="comments_container_"]').forEach(c=>{
    const postId=c.id.replace('comments_container_','');
    const isCollapsed=c.classList.contains('comments-collapsed')||c.style.display==='none';
    if(!isCollapsed)open.push(postId);
  });
  return open;
}

// Close menus when clicking outside
document.addEventListener('click',function(e){
  if(!e.target.closest('.fb-post-menu')){
    document.querySelectorAll('.fb-post-menu-dropdown').forEach(m=>m.classList.remove('show'));
  }
});

/* Emoji picker */
(function(){
  const EMOJIS=[
    "😀","😁","😂","🤣","😅","😊","🙂","🙃","😉","😍",
    "😘","😋","😎","🤩","😇","🤔","🤨","😐","😴","😢",
    "😭","😤","😡","🤯","👍","👎","🙏","👏","🙌","🤝",
    "💪","🧠","🔥","✨","🎉","❤️","💔","😮","🤗","😬"
  ];
  let _emojiInitialized=false;
  let _currentTarget=null;
  let _currentTrigger=null;
  const picker=document.getElementById('emoji_picker');
  const grid=document.getElementById('emoji_grid');

  function populateGrid(){
    if(_emojiInitialized)return;
    grid.innerHTML='';
    EMOJIS.forEach(e=>{
      const btn=document.createElement('button');
      btn.type='button';
      btn.className='p-1 text-lg';
      btn.style.border='none';
      btn.style.background='transparent';
      btn.style.cursor='pointer';
      btn.style.padding='6px';
      btn.style.borderRadius='6px';
      btn.textContent=e;
      btn.addEventListener('click',(ev)=>{
        ev.preventDefault();
        onEmojiClick(e);
      });
      btn.addEventListener('mouseover',()=>btn.style.background='#f0f2f5');
      btn.addEventListener('mouseout',()=>btn.style.background='transparent');
      grid.appendChild(btn);
    });
    _emojiInitialized=true;
  }

  function showEmojiPickerFor(targetEl,triggerEl){
    populateGrid();
    _currentTarget=targetEl;
    _currentTrigger=triggerEl||_currentTrigger||null;
    if(!picker)return;
    try{if(picker.parentNode!==document.body)document.body.appendChild(picker)}catch(e){}
    picker.style.display='block';
    positionPicker(_currentTrigger);
    setTimeout(()=>{try{targetEl&&targetEl.focus()}catch(e){}},0);
  }

  function positionPicker(triggerEl){
    if(!picker)return;
    const margin=8;
    if(!triggerEl||!triggerEl.getBoundingClientRect){
      const w=picker.offsetWidth||picker.getBoundingClientRect().width||200;
      const left=Math.max(8,Math.round((window.innerWidth-w)/2));
      const top=Math.max(8,margin);
      picker.style.left=left+'px';
      picker.style.top=top+'px';
      return;
    }
    let rect;
    try{rect=triggerEl.getBoundingClientRect()}catch(e){rect=null}
    if(!rect){positionPicker(null);return}
    const pickerRect=picker.getBoundingClientRect();
    let left=rect.left;
    let top=rect.bottom+margin;
    if(left+pickerRect.width>window.innerWidth-8){
      left=Math.max(8,window.innerWidth-pickerRect.width-12);
    }
    if(left<8)left=8;
    if(top+pickerRect.height>window.innerHeight-8){
      top=rect.top-pickerRect.height-margin;
      if(top<8)top=8;
    }
    picker.style.left=Math.round(left)+'px';
    picker.style.top=Math.round(top)+'px';
  }

  function insertAtCursor(el,text){
    if(!el)return;
    if(el instanceof HTMLTextAreaElement||el instanceof HTMLInputElement){
      const start=el.selectionStart||0;
      const end=el.selectionEnd||0;
      const val=el.value||'';
      const newVal=val.slice(0,start)+text+val.slice(end);
      el.value=newVal;
      const pos=start+text.length;
      try{el.setSelectionRange(pos,pos)}catch(e){}
      el.focus();
      const ev=new Event('input',{bubbles:true});
      el.dispatchEvent(ev);
    }else{
      el.textContent=(el.textContent||'')+text;
    }
  }

  function onEmojiClick(emoji){
    if(_currentTarget){
      insertAtCursor(_currentTarget,emoji);
      if(_currentTarget instanceof HTMLInputElement&&_currentTarget.value.length<40){
        closePicker();
      }
    }
  }

  function closePicker(){
    _currentTarget=null;
    _currentTrigger=null;
    if(picker)picker.style.display='none';
  }

  document.addEventListener('click',function(e){
    if(!picker)return;
    const insidePicker=e.target.closest&&e.target.closest('#emoji_picker');
    const isTrigger=_currentTrigger&&(_currentTrigger===e.target||(_currentTrigger.contains&&_currentTrigger.contains(e.target)));
    if(!insidePicker&&!isTrigger)closePicker();
  });

  window.addEventListener('resize',()=>{if(_currentTrigger&&picker.style.display!=='none')positionPicker(_currentTrigger)});
  window.addEventListener('scroll',()=>{if(_currentTrigger&&picker.style.display!=='none')positionPicker(_currentTrigger)},true);
  document.addEventListener('keydown',function(e){if(e.key==='Escape')closePicker()});

  window.showEmojiPickerFor=showEmojiPickerFor;
})();
</script>
</body>
</html>