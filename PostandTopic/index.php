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
            $ok = false;
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
                        $ok = true;
                    }
                }
            }
        } else {
        }

        $_SESSION['user_name'] = htmlspecialchars($name, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8');
        session_regenerate_id(true);
    } else {
        ?>
        <!DOCTYPE html>
        <html lang="th">
        <head>
            <meta charset="UTF-8">
            <title>กรุณากรอกชื่อผู้ใช้</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-100 h-screen flex items-center justify-center">

            <div class="bg-white p-6 rounded-lg shadow-lg w-full max-w-md">
                <h2 class="text-2xl font-semibold text-center mb-6 text-gray-800">กรุณากรอกชื่อผู้ใช้ของคุณ</h2>
                <!--- เมนู:(ลงทะเบียนผู้ใช้) -->
                <form method="POST" enctype="multipart/form-data">
                    <div class="mb-4">
                        <label for="set_name" class="block text-gray-700 text-sm font-medium mb-2">ชื่อของคุณ</label>
                        <input type="text" name="set_name" id="set_name" required placeholder="ชื่อของคุณ"
                            class="w-full p-3 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                    </div>

                    <!--- เมนู: (ลงทะเบียนผู้ใช้) -->
                    <div class="mb-4">
                        <label for="avatar" class="block text-gray-700 text-sm font-medium mb-2">อัปโหลดรูปโปรไฟล์ (ไม่บังคับ, รูปเล็กกว่า 2MB)</label>
                        <input type="file" name="avatar" id="avatar" accept="image/*"
                            class="w-full p-2 border border-gray-300 rounded-lg">
                    </div>

                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

                    <div class="flex justify-center">
                        <button type="submit"
                            class="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500">
                            ตกลง
                        </button>
                    </div>
                </form>

                <!--- เมนู: (ลงทะเบียนผู้ใช้) -->
                <script>
                (function(){
                    var avatarInput = document.getElementById('avatar');
                    if(!avatarInput) return;
                    var MAX_AVATAR = 2 * 1024 * 1024;
                    avatarInput.addEventListener('change', function(){
                        var f = this.files && this.files[0];
                        if(f && f.size > MAX_AVATAR){
                            alert('ไฟล์รูปโปรไฟล์มีขนาดเกินที่กำหนด (2MB). กรุณาเลือกไฟล์ขนาดเล็กกว่า 2MB');
                            this.value = '';
                        }
                    });
                })();
                </script>

            </div>

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
        if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)){
            return $ip;
        }
    }

    foreach($candidates as $ip){
        if(filter_var($ip, FILTER_VALIDATE_IP)){
            return $ip;
        }
    }

    // fallback
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
        if ((int)$c['time'] === (int)$time) {
            return $c;
        }
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

function renderComments($comments, $post_id, $level = 0){
    foreach ($comments as $c) {
        $cReacts = $c['reactions'] ?? ["like"=>[],"love"=>[],"wow"=>[],"angry"=>[]];
        $indent = $level * 12;
        $cid = (int)$c['time'];
        $replies = $c['replies'] ?? [];
        $totalReplies = count($replies);
        $fullText = (string)($c['text'] ?? '');
        $shortLimit = 300;
        $isLong = mb_strlen($fullText) > $shortLimit;
        $shortText = $isLong ? mb_substr($fullText, 0, $shortLimit) : $fullText;

        $avatarUrl = getAvatarUrlForUser($c['user']);
        ?>
        <div class="p-2 bg-gray-100 rounded-lg mb-2" id="comment_<?= $post_id ?>_<?= $cid ?>" style="margin-left: <?= $indent ?>px;">
            <div class="flex items-center gap-2">
                <?php if($avatarUrl): ?>
                    <img src="<?= htmlspecialchars($avatarUrl) ?>" alt="avatar" class="w-8 h-8 rounded-full object-cover">
                <?php else: ?>
                    <div class="avatar" style="width:32px;height:32px;border-radius:9999px;display:inline-flex;align-items:center;justify-content:center;background:#e5e7eb;font-weight:600;color:#111827;">
                        <?= htmlspecialchars(mb_substr($c['user'],0,1)) ?>
                    </div>
                <?php endif; ?>
                <div style="flex:1;">
                    <b><?= htmlspecialchars($c['user']) ?></b>: 
                    <span class="comment-text">
                        <?php if($isLong): ?>
                            <span id="short_text_<?= $post_id ?>_<?= $cid ?>" class="comment-short"><?= htmlspecialchars($shortText) ?>...</span>
                            <span id="full_text_<?= $post_id ?>_<?= $cid ?>" class="comment-full"><?= htmlspecialchars($fullText) ?></span>
                            <span class="read-more" onclick="toggleLongText('<?= $post_id ?>','<?= $cid ?>')" id="read_more_btn_<?= $post_id ?>_<?= $cid ?>">อ่านเพิ่มเติม</span>
                        <?php else: ?>
                            <span><?= htmlspecialchars($fullText) ?></span>
                        <?php endif; ?>
                    </span>
                    <div class="text-xs text-gray-500"><?= date("H:i:s d-m-Y", (int)$c['time']) ?></div>
                    <?php if(!empty($c['media']) && !empty($c['media']['path'])):
                        $cm = $c['media'];
                        $cpath = htmlspecialchars($cm['path']);
                        if($cm['kind'] === 'video'): ?>
                            <div style="margin-top:6px;">
                                <video controls style="max-width:100%; height:auto; border-radius:6px;">
                                    <source src="<?= $cpath ?>" type="<?= htmlspecialchars($cm['mime']) ?>">
                                </video>
                            </div>
                        <?php else: ?>
                            <div style="margin-top:6px;">
                                <img src="<?= $cpath ?>" alt="media" style="max-width:100%; height:auto; border-radius:6px;">
                            </div>
                        <?php endif;
                    endif; ?>
                </div>
            </div>
            <?php if($c['user']==$_SESSION['user_name'] || ( ($c['ip'] ?? '') === getClientIP() )): ?>
                <div class="flex gap-2 mt-2">
                    <button class="text-xs text-blue-500" onclick="editComment('<?= $post_id ?>','<?= $cid ?>')">แก้ไข</button>
                    <button class="text-xs text-red-500" onclick="deleteComment('<?= $post_id ?>','<?= $cid ?>')">ลบ</button>
                </div>
            <?php endif; ?>
            <div class="flex gap-2 mt-1">
                <?php foreach(["like"=>"👍","love"=>"❤️","wow"=>"😮","angry"=>"😡"] as $type=>$emoji): ?>
                    <button class="text-sm reaction-btn" onclick="reactComment('<?= $post_id ?>','<?= $cid ?>','<?= $type ?>')" title="<?= implode(', ', $cReacts[$type]??[]) ?>">
                        <span class="emoji-dance"><?= $emoji ?></span> <span><?= count($cReacts[$type]??[]) ?></span>
                    </button>
                <?php endforeach; ?>
                <button class="text-xs text-gray-600" onclick="replyComment('<?= $post_id ?>','<?= $cid ?>')">ตอบ</button>
            </div>

            <?php
            if ($totalReplies > 0) {
                $maxShow = 3;
                if ($totalReplies > $maxShow) {
                    $hiddenCount = $totalReplies - $maxShow;
                    ?>
                    <div>
                        <span class="replies-toggle" id="replies_toggle_<?= $post_id ?>_<?= $cid ?>" onclick="revealPrevReplies('<?= $post_id ?>','<?= $cid ?>')">
                            ดูความคิดเห็นก่อนหน้า <?= $hiddenCount ?> รายการ
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
            ?>
        </div>
        <?php
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
        if(mb_strlen($text) > 2000) $text = mb_substr($text,0,2000);

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
        if($media){
            $newPost['media'] = $media;
        }

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
                if(!$clicked_same){
                    $p["reactions"][$type][] = $_SESSION['user_name'];
                }
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
                    if(!$clicked_same){
                        $c['reactions'][$type][] = $_SESSION['user_name'];
                    }
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
                if($media){
                    $p['media'] = $media;
                }
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
                    if($media){
                        $c['media'] = $media;
                    }
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
        ?>
        <!--- เมนู: timeline (หน้าไทม์ไลน์ / ฟีด) -->
        <div class="bg-white rounded-lg shadow-md mb-4 p-4 post-card" id="post_<?= $post['id'] ?>">
            <p class="mb-3">
                <span style="display:flex; align-items:center; gap:8px;">
                    <?php if($postAvatar): ?>
                        <img src="<?= htmlspecialchars($postAvatar) ?>" alt="avatar" class="w-10 h-10 rounded-full object-cover">
                    <?php else: ?>
                        <div class="avatar" style="width:40px;height:40px;border-radius:9999px;display:inline-flex;align-items:center;justify-content:center;background:#e5e7eb;font-weight:600;color:#111827;">
                            <?= htmlspecialchars(mb_substr($post['user'],0,1)) ?>
                        </div>
                    <?php endif; ?>
                    <div style="flex:1;">
                        <b><?= htmlspecialchars($post['user']) ?></b>: 
                        <span class="post-text"><?= nl2br(htmlspecialchars($post['text'])) ?></span>
                        <br>
                        <span class="text-xs text-gray-500"><?= date("H:i:s d-m-Y", (int)$post['time']) ?></span>
                        <?php if(!empty($post['media']) && !empty($post['media']['path'])): 
                            $m = $post['media'];
                            $mpath = htmlspecialchars($m['path']);
                            if($m['kind'] === 'video'): ?>
                                <div style="margin-top:8px;">
                                    <video controls style="max-width:100%; height:auto; border-radius:8px;">
                                        <source src="<?= $mpath ?>" type="<?= htmlspecialchars($m['mime']) ?>">
                                        Your browser does not support the video tag.
                                    </video>
                                </div>
                            <?php else: ?>
                                <div style="margin-top:8px;">
                                    <img src="<?= $mpath ?>" alt="media" style="max-width:100%; height:auto; border-radius:8px;">
                                </div>
                            <?php endif; ?>
                        <?php endif; ?>
                    </div>
                </span>
            </p>

            <?php 
            if($post['user']==$_SESSION['user_name'] || ( ($post['ip'] ?? '') === getClientIP() )): ?>
                <div class="flex gap-2 mb-2">
                    <button class="text-sm text-blue-500 edit-btn" onclick="editPost('<?= $post['id'] ?>')">แก้ไขโพสต์</button>
                    <button class="text-sm text-red-500" onclick="deletePost('<?= $post['id'] ?>')">ลบโพสต์</button>
                </div>
            <?php endif; ?>

            <div class="flex items-center gap-4 mb-3">
                <?php foreach(["like"=>"👍","love"=>"❤️","wow"=>"😮","angry"=>"😡"] as $type=>$emoji): ?>
                    <button class="text-2xl reaction-btn" onclick="react('<?= $post['id'] ?>','<?= $type ?>')" title="<?= implode(', ', $post['reactions'][$type]) ?>">
                        <span class="emoji-dance"><?= $emoji ?></span> <span class="reaction-count"><?= count($post['reactions'][$type]) ?></span>
                    </button>
                <?php endforeach; ?>
            </div>

            <div class="space-y-2 mb-3">
                <?php if(count($topComments = $post['comments'] ?? []) > 0): ?>
                    <div class="mb-2">
                        <?php $totalTop = count($topComments); ?>
                        <!-- ปุ่มเริ่มต้นแสดงจำนวนคอมเมนต์หลัก และเก็บใน data-count -->
                        <button id="toggle_comments_btn_<?= $post['id'] ?>" class="text-sm text-gray-600"
                                data-count="<?= $totalTop ?>"
                                onclick="toggleAllComments('<?= $post['id'] ?>')">
                            แสดงความคิดเห็นทั้งหมด (<?= $totalTop ?>)
                        </button>
                    </div>
                <?php endif; ?>

                <!-- ห่อส่วนคอมเมนต์ทั้งหมดไว้ใน container เพื่อการซ่อน/แสดง -->
                <div id="comments_container_<?= $post['id'] ?>" class="comments-collapsed" style="display:none;">
                    <?php
                    $topComments = $post['comments'] ?? [];
                    $totalTop = count($topComments);
                    if ($totalTop > 10) {
                        $maxShow = 10;
                        $hiddenCount = $totalTop - $maxShow;
                        ?>
                        <div>
                            <span class="replies-toggle" id="post_replies_toggle_<?= $post['id'] ?>" onclick="revealPrevTopComments('<?= $post['id'] ?>')">
                                ดูความคิดเห็นก่อนหน้า <?= $hiddenCount ?> รายการ
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
            </div>

            <div class="flex items-start gap-2">
                <input type="text" id="comment_<?= $post['id'] ?>" class="flex-1 border rounded-lg p-2" placeholder="เขียนความคิดเห็น...">
                <input type="file" id="comment_media_<?= $post['id'] ?>" accept="image/*,video/*" style="display:none;">
                <button type="button" onclick="document.getElementById('comment_media_<?= $post['id'] ?>').click();" class="ml-2 emoji-btn action-btn bg-gray-action" title="เพิ่มรูปภาพ">📷</button>
                <button type="button" title="เพิ่มอีโมจิ"
                        onclick="showEmojiPickerFor(document.getElementById('comment_<?= $post['id'] ?>'), this)"
                        class="ml-2 emoji-btn action-btn bg-gray-action">😊</button>
                <button class="ml-2 send-btn action-btn bg-green-500 hover:bg-green-600 transition" onclick="addComment('<?= $post['id'] ?>')">ส่ง</button>
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
<title>Mini Social Modern</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<!-- Add Prompt font -->
<link href="https://fonts.googleapis.com/css2?family=Prompt:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.tailwindcss.com"></script>
<style>
@keyframes dance {
  0% { transform: translateY(0) rotate(0deg); }
  25% { transform: translateY(-5px) rotate(-10deg); }
  50% { transform: translateY(0) rotate(0deg); }
  75% { transform: translateY(-5px) rotate(10deg); }
  100% { transform: translateY(0) rotate(0deg); }
}
.emoji-dance { display:inline-block; }

.reaction-btn.clicked .emoji-dance {
  animation: dance 0.6s ease-in-out;
}

#status-toast { position: fixed; bottom: calc(56px + 20px); right: 20px; z-index: 2400; display: none; }


.replies-hidden { display: none; margin-top: 6px; } 
.replies-toggle { cursor: pointer; color: #2563eb; font-size: 0.9rem; margin-bottom:6px; display:inline-block; }
.read-more { cursor:pointer; color:#2563eb; margin-left:6px; font-size:0.9rem; }
.comment-short { display: inline; }
.comment-full { display: none; white-space: pre-wrap; }
.comments-collapsed { display:none; }

/* emoji picker */
#emoji_picker { 
  display:none; 
  position:absolute; 
  z-index:2300; 
  background:#fff; 
  border:1px solid #e5e7eb; 
  padding:8px; 
  border-radius:8px; 
  box-shadow:0 6px 18px rgba(0,0,0,0.08);
  max-width: calc(100vw - 16px);
  width: auto;
  max-height: 50vh;
  overflow: auto;
  box-sizing: border-box;
}

/* edit modal */
#edit_modal_overlay { display:none; position:fixed; inset:0; background:rgba(0,0,0,0.4); z-index:2100; align-items:center; justify-content:center; }
#edit_modal { background:#fff; padding:16px; border-radius:8px; width:90%; max-width:640px; }
#edit_modal_title { margin:0 0 8px 0; font-weight:600; }

/* unified action button sizes for emoji and send buttons */
.action-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  height: 40px;
  min-height: 40px;
  padding: 0 10px;
  border-radius: 8px;
  font-size: 18px;
  line-height: 1;
  box-sizing: border-box;
}

/* emoji buttons are square */
.emoji-btn { 
  width: 40px;
  padding: 0;
}

/* send buttons keep horizontal padding but same height */
.send-btn {
  padding: 0 12px;
  min-width: 56px;
  color: #fff;
}

/* keep hover visuals but use action-btn for sizing */
.bg-gray-action { background:#f3f4f6; }
.bg-gray-action:hover { background:#e5e7eb; }

/* ---------- NEW: menubar/footer styles ---------- */
.top-bar {
  position: fixed;
  inset: 0 0 auto 0;
  height: 64px;
  background: #ffffff;
  border-bottom: 1px solid #e5e7eb;
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 0 16px;
  z-index: 2200;
  box-shadow: 0 2px 6px rgba(30,41,59,0.04);
}
.top-bar .logo { font-weight:700; font-size:18px; color:#1877f2; display:flex; align-items:center; gap:8px; }
.top-bar .nav-center { margin:0 auto; display:flex; gap:12px; align-items:center; }
.top-bar .nav-item { padding:8px 10px; border-radius:8px; cursor:pointer; color:#374151; display:flex; align-items:center; gap:8px; }
.top-bar .nav-item:hover { background:#f3f4f6; }
.top-bar .profile { display:flex; gap:8px; align-items:center; }
.top-bar .profile .avatar { width:36px; height:36px; border-radius:50%; background:#e5e7eb; display:inline-flex; align-items:center; justify-content:center; font-weight:600; color:#111827; }

.content-with-navbar { padding-top: 88px; }
body { 
  font-family: 'Prompt', system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol";
  padding-bottom: 72px; 
}

/* Locked/consistent post width (responsive fallback) */
.post-card {
  width: 960px;               
  max-width: calc(100% - 32px); 
  margin-left: auto;
  margin-right: auto;
  box-sizing: border-box;
}

/* Make edit + cancel buttons have matching, slightly larger font */
.edit-btn, .modal-cancel {
  font-size: 15px !important;
  line-height: 1.2;
}

/* Slight padding tweak to modal cancel for better visual parity with save button */
.modal-cancel { padding: 6px 10px; }

/* footer */
.bottom-bar {
  position: fixed;
  left: 0;
  right: 0;
  bottom: 0;
  height: 56px;
  background: #ffffff;
  border-top: 1px solid #e5e7eb;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 14px;
  z-index: 2100;
}
.bottom-bar .fb-link { color:#6b7280; font-size:13px; padding:6px 8px; border-radius:8px; }
.bottom-bar .fb-link:hover { background:#f8fafc; color:#111827; }

/* scroll-to-top button (appears slightly above footer, bottom-right) */
.scroll-top-btn {
  position: fixed;
  right: 20px;
  bottom: 80px; 
  z-index: 2450;
  display: none;
  width: 44px;
  height: 44px;
  border-radius: 9999px;
  background: #111827;
  color: #ffffff;
  align-items: center;
  justify-content: center;
  box-shadow: 0 6px 18px rgba(0,0,0,0.16);
  cursor: pointer;
  font-size: 20px;
  border: none;
}
/* gentle hover/focus styles */
.scroll-top-btn:hover, .scroll-top-btn:focus {
  background: #0ea5e9;
  transform: translateY(-2px);
  transition: background .18s ease, transform .12s ease;
}
/* visible utility class */
.scroll-top-btn.visible { display: inline-flex; }

/* respect small screens so button doesn't overlap important UI */
@media (max-width:420px) {
  .scroll-top-btn { right: 12px; bottom: 72px; width:40px; height:40px; font-size:18px; }
}

/* avatar image sizing */
.avatar-img { width:40px; height:40px; border-radius:9999px; object-fit:cover; }
</style>
</head>
<body class="bg-gray-100">
  <!-- new menubar -->
  <header class="top-bar" role="navigation" aria-label="Main menu">
    <div class="logo">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden>
        <rect width="24" height="24" rx="4" fill="#1877f2"></rect>
        <path d="M7 12h3v7h4v-7h3V8h-3V6.5C14 4 15 3 16.8 3c1 0 2 .1 2 .1V6h-1.6c-1.6 0-1.9.8-1.9 1.9V8H17l-1 4h-3v7H7z" fill="#fff" />
      </svg>
      MiniSocial
    </div>

    <nav class="nav-center" aria-hidden="true">
    </nav>

    <?php
    $menuAvatar = null;
    if(isset($_SESSION['user_name'])) {
        $menuAvatar = getAvatarUrlForUser($_SESSION['user_name']);
    }
    ?>
    <div class="profile">
      <?php if($menuAvatar): ?>
        <img src="<?= htmlspecialchars($menuAvatar) ?>" alt="avatar" class="avatar-img" title="Profile">
      <?php else: ?>
        <div class="avatar" title="Profile"><?= htmlspecialchars($_SESSION['user_name'][0] ?? 'U') ?></div>
      <?php endif; ?>
      <div class="text-sm hidden sm:block" style="color:#374151"><?= htmlspecialchars($_SESSION['user_name']) ?></div>
    </div>
  </header>

  <div class="container my-4 content-with-navbar">
    <div class="bg-white p-4 rounded-lg shadow-md mb-6 post-card">
      <div class="flex items-start gap-2">
          <textarea id="post_text" class="w-full p-3 border rounded-lg resize-none" rows="3" placeholder="คุณกำลังคิดอะไรอยู่...?"></textarea>
          <button type="button" title="เพิ่มอีโมจิ"
                  onclick="showEmojiPickerFor(document.getElementById('post_text'), this)"
                  class="ml-2 emoji-btn action-btn bg-gray-action">😊</button>
      </div>
      <div class="mt-2 flex items-center gap-2">
          <input type="file" id="post_media" accept="image/*,video/*" style="display:none;">
          <button type="button" onclick="document.getElementById('post_media').click();" class="px-3 py-1 border rounded bg-gray-100 hover:bg-gray-200">เพิ่มรูปภาพ</button>
          <button class="ml-auto mt-2 send-btn action-btn bg-blue-600 hover:bg-blue-700 transition" onclick="addPost()">โพสต์</button>
      </div>
    </div>
    <div id="post_area"></div>
  </div>

  <!-- new footer -->
  <footer class="bottom-bar" aria-label="Footer">
    <div class="text-sm text-gray-500">MiniSocial &middot; <?= date('Y') ?></div>
  </footer>

  <button id="scroll_top_btn" class="scroll-top-btn" aria-label="เลื่อนขึ้นด้านบน" title="เลื่อนขึ้นด้านบน">▲</button>

  <div id="status-toast" class="toast align-items-center text-bg-success border-0" role="alert">
    <div class="d-flex">
      <div class="toast-body">เรียบร้อย</div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" onclick="hideToast()"></button>
    </div>
  </div>

  <!-- emoji picker -->
  <div id="emoji_picker" style="display:none; position: fixed; z-index:2300; background:#fff; border:1px solid #e5e7eb; padding:8px; border-radius:8px; box-shadow:0 6px 18px rgba(0,0,0,0.08); max-width:calc(100vw - 16px); max-height:50vh; overflow:auto; box-sizing:border-box;">
      <div id="emoji_grid" style="display:grid; grid-template-columns: repeat(auto-fit, minmax(32px, 1fr)); gap:6px; max-width:min(320px, calc(100vw - 32px));"></div>
  </div>

  <!-- edit modal -->
  <div id="edit_modal_overlay" style="display:none; position:fixed; inset:0; background:rgba(0,0,0,0.4); z-index:2100; align-items:center; justify-content:center;">
    <div id="edit_modal" style="background:#fff; padding:16px; border-radius:8px; width:90%; max-width:640px;">
      <h3 id="edit_modal_title" style="margin:0 0 8px 0; font-weight:600;">แก้ไข</h3>
      <div style="display:flex; gap:8px; align-items:flex-start;">
        <textarea id="edit_modal_text" rows="6" style="flex:1; padding:8px; border:1px solid #d1d5db; border-radius:6px; resize:vertical;"></textarea>
        <!-- emoji + media controls for the edit modal -->
        <div style="display:flex; flex-direction:column; gap:8px;">
          <button type="button" title="เพิ่มอีโมจิ" onclick="showEmojiPickerFor(document.getElementById('edit_modal_text'), this)"
                  class="bg-gray-100 p-2 rounded-lg hover:bg-gray-200">😊</button>
          <input type="file" id="edit_modal_media" accept="image/*,video/*" style="display:none;">
          <button type="button" title="เพิ่มรูปภาพ" onclick="document.getElementById('edit_modal_media').click()"
                  class="bg-gray-100 p-2 rounded-lg hover:bg-gray-200">📷</button>
        </div>
      </div>
      <div style="display:flex; justify-content:flex-end; gap:8px; margin-top:12px;">
        <!-- add modal-cancel class -->
        <button type="button" onclick="hideEditModal()" class="px-3 py-1 rounded bg-gray-200 modal-cancel">ยกเลิก</button>
        <button id="edit_modal_save" type="button" class="send-btn action-btn bg-blue-600 text-white">บันทึก</button>
      </div>
    </div>
  </div>

  <div id="reply_modal_overlay" style="display:none; position:fixed; inset:0; background:rgba(0,0,0,0.4); z-index:2150; align-items:center; justify-content:center;">
    <div id="reply_modal" style="background:#fff; padding:16px; border-radius:8px; width:90%; max-width:640px;">
      <h3 id="reply_modal_title" style="margin:0 0 8px 0; font-weight:600;">ตอบคอมเมนต์</h3>
      <div style="display:flex; gap:8px; align-items:flex-start;">
        <textarea id="reply_modal_text" rows="5" style="flex:1; padding:8px; border:1px solid #d1d5db; border-radius:6px; resize:vertical;" placeholder="เขียนคำตอบ..."></textarea>
        <div style="display:flex; flex-direction:column; gap:8px;">
          <button type="button" title="เพิ่มอีโมจิ" onclick="showEmojiPickerFor(document.getElementById('reply_modal_text'), this)"
                  class="bg-gray-100 p-2 rounded-lg hover:bg-gray-200">😊</button>
          <input type="file" id="reply_modal_media" accept="image/*,video/*" style="display:none;">
          <button type="button" title="เพิ่มรูปภาพ" onclick="document.getElementById('reply_modal_media').click()"
                  class="bg-gray-100 p-2 rounded-lg hover:bg-gray-200">📷</button>
        </div>
      </div>
      <div style="display:flex; justify-content:flex-end; gap:8px; margin-top:12px;">
        <button type="button" onclick="hideReplyModal()" class="px-3 py-1 rounded bg-gray-200 modal-cancel">ยกเลิก</button>
        <button id="reply_modal_save" type="button" class="send-btn action-btn bg-green-500 text-white">ตอบ</button>
      </div>
      <div style="margin-top:8px; font-size:12px; color:#6b7280;">ขนาดไฟล์สูงสุด 8MB</div>
    </div>
  </div>

  <script>
const CSRF_TOKEN = '<?= htmlspecialchars($_SESSION['csrf_token']) ?>';

function showToast(msg="เรียบร้อย") {
    let toastEl = document.getElementById("status-toast");
    toastEl.querySelector(".toast-body").textContent = msg;
    toastEl.style.display = "flex";
    setTimeout(()=> { hideToast(); }, 3000);
}

function hideToast() { document.getElementById("status-toast").style.display = "none"; }

function addPost(){
    let text = document.getElementById("post_text").value;
    if(text.trim() === "") return;
    const fd = new FormData();
    fd.append('api','add_post');
    fd.append('text', text);
    fd.append('csrf_token', CSRF_TOKEN);
    const file = document.getElementById('post_media');
    if(file && file.files && file.files[0]){
        fd.append('media', file.files[0]);
    }
    fetch("<?=$_SERVER['PHP_SELF']?>", {
        method:"POST",
        body: fd
    }).then(res => res.text())
      .then(res => {
        if(res === "OK"){ loadPosts(); document.getElementById("post_text").value = ""; 
            if(file) file.value = "";
            showToast("โพสต์สำเร็จ 🎉");
        }
    });
}

function editPost(postId){
    const el = document.querySelector(`#post_${postId} .post-text`);
    const current = el ? el.innerText.replace(/\u00A0/g,' ').trim() : '';
    showEditModal('post', postId, null, current);
}

let _editContext = null;
function showEditModal(type, postId, time = null, currentText = ''){
    _editContext = { type, postId, time };
    const overlay = document.getElementById('edit_modal_overlay');
    const textarea = document.getElementById('edit_modal_text');
    const media = document.getElementById('edit_modal_media');
    textarea.value = currentText || '';
    if(media) media.value = '';
    if(overlay) overlay.style.display = 'flex';
    setTimeout(()=> { try { textarea.focus(); textarea.setSelectionRange(textarea.value.length, textarea.value.length); } catch(e){} }, 50);
}

function hideEditModal(){
    _editContext = null;
    const overlay = document.getElementById('edit_modal_overlay');
    if(overlay) overlay.style.display = 'none';
    const textarea = document.getElementById('edit_modal_text');
    if(textarea) textarea.value = '';
    const media = document.getElementById('edit_modal_media');
    if(media) media.value = '';
}

document.getElementById('edit_modal_save').addEventListener('click', function(){
    if(!_editContext) return;
    const text = (document.getElementById('edit_modal_text').value || '').trim();
    if(text === '') { alert('ข้อความต้องไม่ว่าง'); return; }
    const fd = new FormData();
    const api = (_editContext.type === 'post') ? 'edit_post' : 'edit_comment';
    fd.append('api', api);
    fd.append('text', text);
    fd.append('csrf_token', CSRF_TOKEN);
    fd.append('post_id', _editContext.postId);
    if(_editContext.type === 'comment') fd.append('time', _editContext.time);
    const mediaEl = document.getElementById('edit_modal_media');
    if(mediaEl && mediaEl.files && mediaEl.files[0]) fd.append('media', mediaEl.files[0]);

    fetch("<?=$_SERVER['PHP_SELF']?>", {
        method: 'POST',
        body: fd
    }).then(res => res.text())
      .then(res => {
          if(res === 'OK'){
              hideEditModal();
              loadPosts();
              showToast('แก้ไขเรียบร้อย ✏️');
          } else {
              showToast('ไม่สามารถแก้ไขได้');
          }
      }).catch(()=>{ showToast('ไม่สามารถแก้ไขได้'); });
});

function deletePost(postId){
    if(!confirm("คุณแน่ใจว่าต้องการลบโพสต์นี้?")) return;
    fetch("<?=$_SERVER['PHP_SELF']?>", {
        method:"POST",
        headers:{"Content-Type":"application/x-www-form-urlencoded"},
        body:"api=delete_post&post_id="+encodeURIComponent(postId)+"&csrf_token="+encodeURIComponent(CSRF_TOKEN)
    }).then(res => res.text())
      .then(res => { if(res==="OK"){ loadPosts(); showToast("ลบโพสต์สำเร็จ 🗑️"); } });
}

function deleteComment(postId, commentTime){
    if(!confirm("คุณแน่ใจว่าต้องการลบคอมเมนต์นี้?")) return;
    fetch("<?=$_SERVER['PHP_SELF']?>", {
        method:"POST",
        headers:{"Content-Type":"application/x-www-form-urlencoded"},
        body:"api=delete_comment&post_id="+encodeURIComponent(postId)+"&comment_time="+encodeURIComponent(commentTime)+"&csrf_token="+encodeURIComponent(CSRF_TOKEN)
    }).then(res => res.text())
      .then(res => { if(res==="OK"){ loadPosts(); showToast("ลบคอมเมนต์สำเร็จ 🗑️"); } });
}

function react(postId, type){
    const open = _getOpenCommentsPosts();

    let button = document.querySelector(`#post_${postId} button[onclick="react('${postId}','${type}')"]`);
    if(button){ button.classList.add("clicked"); setTimeout(()=> button.classList.remove("clicked"), 600); }

    fetch("<?=$_SERVER['PHP_SELF']?>", {
        method:"POST",
        headers:{ "Content-Type":"application/x-www-form-urlencoded" },
        body:"api=reaction&post_id="+encodeURIComponent(postId)+"&type="+encodeURIComponent(type)+"&csrf_token="+encodeURIComponent(CSRF_TOKEN)
    }).then(res => res.text())
      .then(res => { if(res === "OK"){ loadPosts(open); } });
}

function reactComment(postId, commentTime, type){
    const open = _getOpenCommentsPosts();

    let button = document.querySelector(`#comment_${postId}_${commentTime} button[onclick="reactComment('${postId}','${commentTime}','${type}')"]`);
    if(button){ button.classList.add("clicked"); setTimeout(()=> button.classList.remove("clicked"), 600); }

    fetch("<?=$_SERVER['PHP_SELF']?>", {
        method:"POST",
        headers:{ "Content-Type":"application/x-www-form-urlencoded" },
        body:"api=reaction_comment&post_id="+encodeURIComponent(postId)+"&comment_time="+encodeURIComponent(commentTime)+"&type="+encodeURIComponent(type)+"&csrf_token="+encodeURIComponent(CSRF_TOKEN)
    }).then(res => res.text())
      .then(res => { if(res==="OK") loadPosts(open); });
}

function addComment(postId){
    let input = document.getElementById("comment_"+postId);
    if(!input) return;
    let text = input.value;
    const fileInput = document.getElementById('comment_media_'+postId);
    const hasFile = fileInput && fileInput.files && fileInput.files[0];
    if(text.trim() === "" && !hasFile) return;
    const fd = new FormData();
    fd.append('api','comment');
    fd.append('post_id', postId);
    fd.append('text', text);
    fd.append('csrf_token', CSRF_TOKEN);
    if(hasFile){
        fd.append('media', fileInput.files[0]);
    }
    fetch("<?=$_SERVER['PHP_SELF']?>", {
        method:"POST",
        body: fd
    }).then(res => res.json().catch(()=>null))
      .then(comment => {
          loadPosts().then(()=> {
              showComments(postId);
              if(input) input.value="";
              if(fileInput) fileInput.value = "";
              showToast("คอมเมนต์สำเร็จ 💬");
          });
      });
}

function loadPosts(openPosts = []){
    return fetch("<?=$_SERVER['PHP_SELF']?>?fetch_posts=1")
    .then(res => res.text())
    .then(html => {
        document.getElementById("post_area").innerHTML = html;
        try { updateScrollTopVisibility(); } catch(e){}
        if(Array.isArray(openPosts) && openPosts.length){
            try {
                openPosts.forEach(pid => {
                    showComments(pid);
                });
            } catch(e){}
        }
    });
}

window.onload = loadPosts;

function editComment(postId, commentTime){
    const el = document.querySelector(`#comment_${postId}_${commentTime} .comment-text`);
    const current = el ? el.innerText.replace(/\u00A0/g,' ').trim() : '';
    showEditModal('comment', postId, commentTime, current);
}

function replyComment(postId, parentTime){
    showReplyModal(postId, parentTime);
}

/* Reply modal logic */
let _replyContext = null; 
function showReplyModal(postId, parentTime, prefill = ''){
    _replyContext = { postId: postId, parentTime: parentTime };
    const overlay = document.getElementById('reply_modal_overlay');
    const textarea = document.getElementById('reply_modal_text');
    const media = document.getElementById('reply_modal_media');
    if(textarea) textarea.value = prefill || '';
    if(media) media.value = '';
    if(overlay) overlay.style.display = 'flex';
    setTimeout(()=> { try { textarea.focus(); textarea.setSelectionRange(textarea.value.length, textarea.value.length); } catch(e){} }, 50);
}
function hideReplyModal(){
    _replyContext = null;
    const overlay = document.getElementById('reply_modal_overlay');
    if(overlay) overlay.style.display = 'none';
    const textarea = document.getElementById('reply_modal_text');
    if(textarea) textarea.value = '';
    const media = document.getElementById('reply_modal_media');
    if(media) media.value = '';
}

// client-side media size check (8MB)
function _replyMediaTooLarge(file){
    if(!file) return false;
    return file.size > (8 * 1024 * 1024);
}

// hook save button
document.getElementById('reply_modal_save').addEventListener('click', function(){
    if(!_replyContext) return;
    const text = (document.getElementById('reply_modal_text').value || '').trim();
    const mediaEl = document.getElementById('reply_modal_media');
    const hasFile = mediaEl && mediaEl.files && mediaEl.files[0];
    if(text === '' && !hasFile) { alert('กรุณาใส่ข้อความหรือแนบไฟล์'); return; }
    if(hasFile && _replyMediaTooLarge(mediaEl.files[0])) { alert('ขนาดไฟล์เกิน 8MB'); return; }

    const fd = new FormData();
    fd.append('api', 'comment');
    fd.append('post_id', _replyContext.postId);
    fd.append('parent_time', _replyContext.parentTime);
    fd.append('text', text);
    fd.append('csrf_token', CSRF_TOKEN);
    if(hasFile) fd.append('media', mediaEl.files[0]);

    fetch("<?=$_SERVER['PHP_SELF']?>", {
        method: 'POST',
        body: fd
    }).then(res => res.json().catch(()=>null))
      .then(resp => {
          hideReplyModal();
          loadPosts().then(()=> {
              try { showComments(_replyContext.postId); } catch(e){}
              showToast("ตอบคอมเมนต์สำเร็จ 💬");
          });
      }).catch(()=> {
          showToast('ไม่สามารถส่งคำตอบได้');
      });
});

function toggleLongText(postId, cid){
    const shortEl = document.getElementById(`short_text_${postId}_${cid}`);
    const fullEl = document.getElementById(`read_more_btn_${postId}_${cid}`);
    const btn = document.getElementById(`read_more_btn_${postId}_${cid}`);
    if(!shortEl || !fullEl || !btn) return;
    if(fullEl.style.display === 'none' || fullEl.style.display === ''){
        fullEl.style.display = 'inline';
        shortEl.style.display = 'none';
        btn.textContent = 'ย่อข้อความ';
    } else {
        fullEl.style.display = 'none';
        shortEl.style.display = 'inline';
        btn.textContent = 'อ่านเพิ่มเติม';
    }
}

function revealPrevTopComments(postId){
    const hid = document.getElementById(`post_replies_hidden_${postId}`);
    const btn = document.getElementById(`post_replies_toggle_${postId}`);
    if(!hid || !btn) return;
    const batch = 5;
    let moved = 0;
    const children = hid.querySelectorAll(`[id^="comment_${postId}_"]`);
    for(let i = children.length - 1; i >= 0 && moved < batch; i--){
        const node = children[i];
        hid.parentNode.insertBefore(node, hid);
        moved++;
    }
    const remaining = hid.querySelectorAll(`[id^="comment_${postId}_"]`).length;
    if(remaining === 0){
        hid.remove();
        btn.style.display = 'none';
    } else {
        btn.textContent = `ดูความคิดเห็นก่อนหน้า ${remaining} รายการ`;
    }
}

function revealPrevReplies(postId, cid){
    const hidId = `replies_hidden_${postId}_${cid}`;
    const btnId = `replies_toggle_${postId}_${cid}`;
    const hid = document.getElementById(hidId);
    const btn = document.getElementById(btnId);
    if(!hid || !btn) return;
    const batch = 3;
    let moved = 0;
    const children = hid.querySelectorAll(`[id^="comment_${postId}_"]`);
    for(let i = children.length - 1; i >=0 && moved < batch; i--){
        const node = children[i];
        hid.parentNode.insertBefore(node, hid);
        moved++;
    }
    const remaining = hid.querySelectorAll(`[id^="comment_${postId}_"]`).length;
    if(remaining === 0){
        hid.remove();
        btn.style.display = 'none';
    } else {
        btn.textContent = `ดูความคิดเห็นก่อนหน้า ${remaining} รายการ`;
    }
}

// helper: แสดงคอมเมนต์ของโพสต์ (ใช้เมื่อเพิ่มคอมเมนต์แล้วต้องแสดง)
function showComments(postId){
    const cont = document.getElementById(`comments_container_${postId}`);
    const btn = document.getElementById(`toggle_comments_btn_${postId}`);
    if(!cont) return;
    cont.style.display = '';
    cont.classList.remove('comments-collapsed');
    if(btn) btn.textContent = 'ซ่อนความคิดเห็นทั้งหมด';

    const hiddenEls = cont.querySelectorAll('.replies-hidden');
    hiddenEls.forEach(e => e.style.display = 'block');

    const toggles = cont.querySelectorAll('.replies-toggle');
    toggles.forEach(t => t.style.display = 'none');
}

// toggle all comments visibility
function toggleAllComments(postId){
    const cont = document.getElementById(`comments_container_${postId}`);
    const btn = document.getElementById(`toggle_comments_btn_${postId}`);
    if(!cont || !btn) return;

    const isCollapsed = cont.classList.contains('comments-collapsed') || cont.style.display === 'none';
    if(isCollapsed){
        cont.style.display = '';
        cont.classList.remove('comments-collapsed');
        btn.textContent = 'ซ่อนความคิดเห็นทั้งหมด';

        const hiddenEls = cont.querySelectorAll('.replies-hidden');
        hiddenEls.forEach(e => e.style.display = 'block');

        const toggles = cont.querySelectorAll('.replies-toggle');
               toggles.forEach(t => t.style.display = 'none');
    } else {
        cont.style.display = 'none';
        cont.classList.add('comments-collapsed');
        btn.textContent = btn.dataset && btn.dataset.count ? `แสดงความคิดเห็นทั้งหมด (${btn.dataset.count})` : 'แสดงความคิดเห็นทั้งหมด';

        const hiddenEls = cont.querySelectorAll('.replies-hidden');
        hiddenEls.forEach(e => e.style.display = 'none');

        const toggles = cont.querySelectorAll('.replies-toggle');
        toggles.forEach(t => t.style.display = 'inline-block');
    }
}

/* ---------- scroll-to-top helpers ---------- */
function updateScrollTopVisibility(){
    const btn = document.getElementById('scroll_top_btn');
    if(!btn) return;
    const posts = document.querySelectorAll('#post_area .post-card').length;
    const POST_THRESHOLD = 8;
    const SCROLL_THRESHOLD = window.innerHeight * 0.6;
    const shouldShow = posts >= POST_THRESHOLD || window.scrollY > SCROLL_THRESHOLD;
    if(shouldShow){
        btn.classList.add('visible');
        btn.setAttribute('aria-hidden','false');
    } else {
        btn.classList.remove('visible');
        btn.setAttribute('aria-hidden','true');
    }
}

// show/hide on scroll (lightweight)
let _scrollTimeout = null;
window.addEventListener('scroll', function(){
    if(_scrollTimeout) return;
    _scrollTimeout = setTimeout(function(){
        updateScrollTopVisibility();
        _scrollTimeout = null;
    }, 120);
});

window.addEventListener('resize', function(){ updateScrollTopVisibility(); });

document.getElementById('scroll_top_btn').addEventListener('click', function(e){
    e.preventDefault();
    window.scrollTo({ top: 0, behavior: 'smooth' });
    this.classList.remove('visible');
    this.setAttribute('aria-hidden','true');
});

try { updateScrollTopVisibility(); } catch(e){}

function _getOpenCommentsPosts(){
    const open = [];
    document.querySelectorAll('[id^="comments_container_"]').forEach(c=>{
        const postId = c.id.replace('comments_container_','');
        const isCollapsed = c.classList.contains('comments-collapsed') || c.style.display === 'none';
        if(!isCollapsed) open.push(postId);
    });
    return open;
}

/* ======================  Emoji picker logic ====================== */
(function(){
    const EMOJIS = [
      "😀","😁","😂","🤣","😅","😊","🙂","🙃","😉","😍",
      "😘","😋","😎","🤩","😇","🤔","🤨","😐","😴","😢",
      "😭","😤","😡","🤯","👍","👎","🙏","👏","🙌","🤝",
      "💪","🧠","🔥","✨","🎉","❤️","💔","😮","🤗","😬"
    ];

    let _emojiInitialized = false;
    let _currentTarget = null; 
    let _currentTrigger = null; 
    const picker = document.getElementById('emoji_picker');
    const grid = document.getElementById('emoji_grid');

    let _pickerRAF = null;
    let _lastTriggerRect = null;

    function populateGrid(){
        if(_emojiInitialized) return;
        grid.innerHTML = '';
        EMOJIS.forEach(e => {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'p-1 text-lg';
            btn.style.border = 'none';
            btn.style.background = 'transparent';
            btn.style.cursor = 'pointer';
            btn.style.padding = '6px';
            btn.style.borderRadius = '6px';
            btn.textContent = e;
            btn.addEventListener('click', (ev) => {
                ev.preventDefault();
                onEmojiClick(e);
            });
            btn.addEventListener('mouseover', ()=> btn.style.background = '#f3f4f6');
            btn.addEventListener('mouseout', ()=> btn.style.background = 'transparent');
            grid.appendChild(btn);
        });
        _emojiInitialized = true;
    }

    function startPickerFollow(){
        if(_pickerRAF) return;
        _lastTriggerRect = null;
        function loop(){
            if(!picker || picker.style.display === 'none' || !_currentTrigger){
                _pickerRAF = null;
                return;
            }
            try {
                positionPicker(_currentTrigger);
            } catch(e) { /* ignore */ }
            _pickerRAF = requestAnimationFrame(loop);
        }
        _pickerRAF = requestAnimationFrame(loop);
    }

    function stopPickerFollow(){
        if(_pickerRAF){
            cancelAnimationFrame(_pickerRAF);
            _pickerRAF = null;
            _lastTriggerRect = null;
        }
    }

    function showEmojiPickerFor(targetEl, triggerEl){
        populateGrid();
        _currentTarget = targetEl;
        _currentTrigger = triggerEl || _currentTrigger || null;
        if(!picker) return;
        try { if(picker.parentNode !== document.body) document.body.appendChild(picker); } catch(e){}
        picker.style.display = 'block';
        picker.style.visibility = 'hidden';
        _lastTriggerRect = null;
        try { positionPicker(_currentTrigger); } catch(e){}
        picker.style.visibility = 'visible';
        startPickerFollow();
        setTimeout(()=> { try { targetEl && targetEl.focus(); } catch(e){} }, 0);
    }

    function positionPicker(triggerEl){
        if(!picker) return;
        const margin = 8;
        if(!triggerEl || !triggerEl.getBoundingClientRect) {
            const w = picker.offsetWidth || picker.getBoundingClientRect().width || 200;
            const left = Math.max(8, Math.round((window.innerWidth - w)/2));
            const top = Math.max(8, margin);
            picker.style.left = left + 'px';
            picker.style.top = top + 'px';
            return;
        }
        let rect;
        try {
            rect = triggerEl.getBoundingClientRect();
        } catch(e) {
            rect = null;
        }
        if(!rect){
            positionPicker(null);
            return;
        }

        if(_lastTriggerRect && _lastTriggerRect.left === rect.left && _lastTriggerRect.top === rect.top && _lastTriggerRect.width === rect.width && _lastTriggerRect.height === rect.height){
            return;
        }
        _lastTriggerRect = { left: rect.left, top: rect.top, width: rect.width, height: rect.height };

        const pickerRect = picker.getBoundingClientRect();
        let left = rect.left;
        let top = rect.bottom + margin;
        if(left + pickerRect.width > window.innerWidth - 8){
            left = Math.max(8, window.innerWidth - pickerRect.width - 12);
        }
        if(left < 8) left = 8;
        if(top + pickerRect.height > window.innerHeight - 8){
            top = rect.top - pickerRect.height - margin;
            if(top < 8) top = 8;
        }
        picker.style.left = Math.round(left) + 'px';
        picker.style.top = Math.round(top) + 'px';
    }

    function insertAtCursor(el, text){
        if(!el) return;
        if(el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement){
            const start = el.selectionStart || 0;
            const end = el.selectionEnd || 0;
            const val = el.value || '';
            const newVal = val.slice(0, start) + text + val.slice(end);
            el.value = newVal;
            const pos = start + text.length;
            try { el.setSelectionRange(pos, pos); } catch(e){}
            el.focus();
            const ev = new Event('input', { bubbles: true });
            el.dispatchEvent(ev);
        } else {
            el.textContent = (el.textContent || '') + text;
        }
    }

    function onEmojiClick(emoji){
        if(_currentTarget){
            insertAtCursor(_currentTarget, emoji);
            if(_currentTarget instanceof HTMLInputElement && _currentTarget.value.length < 40){
                closePicker();
            }
        }
    }

    function closePicker(){
        _currentTarget = null;
        _currentTrigger = null;
        stopPickerFollow();
        if(picker) picker.style.display = 'none';
    }

    document.addEventListener('click', function(e){
        if(!picker) return;
        const insidePicker = e.target.closest && e.target.closest('#emoji_picker');
        const isTrigger = _currentTrigger && (_currentTrigger === e.target || (_currentTrigger.contains && _currentTrigger.contains(e.target)));
        if(!insidePicker && !isTrigger){
            closePicker();
        }
    });

    window.addEventListener('resize', ()=> { if(_currentTrigger && picker.style.display !== 'none') positionPicker(_currentTrigger); });
    window.addEventListener('scroll', ()=> { if(_currentTrigger && picker.style.display !== 'none') positionPicker(_currentTrigger); }, true);

    document.addEventListener('keydown', function(e){
        if(e.key === 'Escape') closePicker();
    });

    window.showEmojiPickerFor = showEmojiPickerFor;
})();
</script>
</body>
</html>
