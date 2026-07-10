<?php
http_response_code(410);
header('Content-Type: text/html; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>上传入口已迁移</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <main class="container">
        <div class="card">
            <h2 class="card-title">上传入口已迁移</h2>
            <p class="text-center">PHP 上传入口已禁用。请登录 Flask 应用后使用 /upload 上传头像。</p>
        </div>
    </main>
</body>
</html>
