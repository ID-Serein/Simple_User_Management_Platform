<?php
// ===== PHP 文件上传处理（含漏洞） =====
// 本脚本故意不进行任何安全校验：
// - 不检查文件后缀名
// - 不检查 MIME 类型
// - 不处理路径遍历
// - 使用用户原始文件名保存

$upload_dir = __DIR__ . '/static/uploads/';
$error = '';
$file_url = '';
$filename = '';

// 确保上传目录存在
if (!is_dir($upload_dir)) {
    mkdir($upload_dir, 0755, true);
}

// 处理文件上传 POST 请求
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
        $error = '请选择一个文件';
    } else {
        // 使用 full_path 以保留路径遍历行为（PHP 8+ 特性）
        $filename = $_FILES['file']['full_path'];
        $dest_path = $upload_dir . $filename;

        // 使用 copy 以保留路径遍历行为（move_uploaded_file 会阻止 ../）
        copy($_FILES['file']['tmp_name'], $dest_path);

        $display_name = basename($filename);
        $file_url = '/static/uploads/' . $display_name;
    }
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>上传头像 - 用户管理系统</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="nav-brand">用户管理系统</div>
        <div class="nav-menu">
            <a href="/" class="nav-link">返回首页</a>
        </div>
    </nav>
    <main class="container">
        <div class="card">
            <h2 class="card-title">上传头像</h2>

            <?php if ($error): ?>
            <div class="error-message"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>

            <?php if ($file_url): ?>
            <div class="upload-success">
                <p class="text-center">上传成功！</p>
                <div class="preview-container">
                    <img src="<?= htmlspecialchars($file_url) ?>" alt="头像预览" class="preview-img">
                </div>
                <div class="file-link-container">
                    <span class="file-link-label">文件链接：</span>
                    <a href="<?= htmlspecialchars($file_url) ?>" class="file-link" target="_blank"><?= htmlspecialchars($file_url) ?></a>
                </div>
            </div>
            <hr class="divider">
            <?php endif; ?>

            <form method="post" action="upload.php" enctype="multipart/form-data">
                <div class="form-group">
                    <label for="file">选择头像文件</label>
                    <input type="file" id="file" name="file" class="form-input" required>
                </div>
                <button type="submit" class="btn btn-primary btn-block">上传</button>
            </form>
        </div>
    </main>
</body>
</html>
