<?php
// ===== PHP 文件包含处理（修复版） =====
// 修复内容：
// - 仅支持 data:// 伪协议（用于漏洞演示）
// - 移除 php://input / php://filter 支持
// - 路径遍历防护（路径规范化 + startswith 校验）

$file = isset($_GET['file']) ? $_GET['file'] : '';
$content = '';
$error = '';

if ($file) {
    if (strpos($file, 'data://') === 0) {
        // data:// 伪协议：URI 内嵌代码执行（仅用于漏洞演示）
        ob_start();
        @include($file);
        $content = ob_get_clean();
        if (empty($content)) {
            $content = @file_get_contents($file);
        }
    } else {
        // 普通文件路径
        $base_dir = realpath(__DIR__ . '/pages/');
        $file_path = realpath($base_dir . '/' . $file);

        // [修复] 路径规范化校验，防止 ../ 遍历
        if ($file_path === false || strpos($file_path, $base_dir) !== 0) {
            $error = '页面不存在';
        } elseif (file_exists($file_path)) {
            $content = file_get_contents($file_path);
        } elseif (file_exists($file_path . '.html')) {
            $content = file_get_contents($file_path . '.html');
        } else {
            $error = '页面不存在';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHP LFI 演示 - 用户管理系统</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="nav-brand">用户管理系统 - LFI 演示</div>
        <div class="nav-menu">
            <a href="lfi.php?file=help" class="nav-link">帮助</a>
            <a href="lfi.php?file=../app.py" class="nav-link">读app.py</a>
            <a href="lfi.php?file=../data/users.json" class="nav-link">读users.json</a>
            <a href="lfi.php?file=../../../etc/passwd" class="nav-link">读/etc/passwd</a>
            <a href="lfi.php?file=php://filter/convert.base64-encode/resource=../app.py" class="nav-link">filter编码</a>
        </div>
    </nav>
    <main class="container">
        <div class="card">
            <h2 class="card-title">文件包含演示</h2>
            <form method="get" action="lfi.php">
                <div class="form-group">
                    <label for="file">文件路径 / 伪协议</label>
                    <input type="text" id="file" name="file" class="form-input" placeholder="例如: help 或 data://text/plain,..." value="<?= htmlspecialchars($file) ?>">
                </div>
                <button type="submit" class="btn btn-primary btn-block">读取</button>
            </form>
        </div>

        <div class="card">
            <h2 class="card-title">执行结果</h2>
            <?php if ($error): ?>
            <div class="error-message"><?= htmlspecialchars($error) ?></div>
            <?php elseif ($file): ?>
            <div class="page-content">
                <pre style="background:#f5f5f5;padding:12px;border-radius:6px;overflow:auto;max-height:500px;font-size:13px;line-height:1.5;"><?= $is_rce_protocol ? $content : htmlspecialchars($content) ?></pre>
            </div>
            <?php if (strpos($file, 'base64-encode') !== false): ?>
            <div class="mt-20">
                <p style="font-size:13px;color:#888;">检测到 Base64 编码输出，可复制到解码工具查看原始内容</p>
            </div>
            <?php endif; ?>
            <?php else: ?>
            <p class="text-center">在上方输入文件路径或伪协议后点击"读取"</p>
            <?php endif; ?>
        </div>

        <div class="card">
            <h2 class="card-title">测试用例</h2>
            <table class="result-table">
                <thead>
                    <tr><th>类型</th><th>URL</th><th>说明</th></tr>
                </thead>
                <tbody>
                    <tr><td>路径遍历</td><td><code>?file=help</code></td><td>读取 pages/ 目录下的页面</td></tr>
                    <tr><td>Data RCE</td><td><code>?file=data://text/plain,<?php echo 1;?></code></td><td>URI 内嵌代码执行</td></tr>
                </tbody>
            </table>
        </div>
    </main>
</body>
</html>
