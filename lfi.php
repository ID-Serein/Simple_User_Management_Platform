<?php
// ===== PHP 文件包含漏洞演示（支持伪协议） =====
// 本脚本用于演示 PHP 伪协议利用：
// - php://filter — 编码读取任意文件
// - php://input — POST 体作为代码执行（需 allow_url_include=On）
// - data:// — URI 内嵌代码执行
// - 路径遍历 — 读取任意文件

$file = isset($_GET['file']) ? $_GET['file'] : '';
$content = '';
$error = '';

if ($file) {
    // [漏洞] 直接使用用户输入作为文件包含路径
    // 不校验路径、不过滤 ../、不限制协议
    $using_protocol = (strpos($file, '://') !== false);
    $is_rce_protocol = (strpos($file, 'php://input') === 0 || strpos($file, 'data://') === 0);

    if ($using_protocol) {
        // 伪协议处理（php://, data:// 等）
        if (strpos($file, 'php://input') === 0) {
            // php://input: 读取 POST 体并通过 eval 执行
            $input_code = @file_get_contents('php://input');
            if ($input_code) {
                ob_start();
                eval('?>' . $input_code);
                $content = ob_get_clean();
            }
        } elseif (strpos($file, 'php://filter') === 0) {
            // php://filter: 直接使用 file_get_contents 读取（CWD 为项目根目录）
            $content = @file_get_contents($file);
        } else {
            // data:// 等其他协议: 使用 include
            ob_start();
            @include($file);
            $content = ob_get_clean();
            if (empty($content)) {
                $content = @file_get_contents($file);
            }
        }
    } else {
        // 普通文件路径
        $base_path = __DIR__ . '/pages/';
        $include_path = $base_path . $file;

        if (file_exists($include_path)) {
            $content = file_get_contents($include_path);
        } elseif (file_exists($include_path . '.html')) {
            $content = file_get_contents($include_path . '.html');
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
                    <input type="text" id="file" name="file" class="form-input" placeholder="例如: ../app.py 或 php://filter/..." value="<?= htmlspecialchars($file) ?>">
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
                    <tr><td>路径遍历</td><td><code>?file=../app.py</code></td><td>读取 Flask 应用源码</td></tr>
                    <tr><td>路径遍历</td><td><code>?file=../../../etc/passwd</code></td><td>读取系统密码文件</td></tr>
                    <tr><td>Filter编码</td><td><code>?file=php://filter/convert.base64-encode/resource=../app.py</code></td><td>Base64 编码读取源码</td></tr>
                    <tr><td>Filter编码</td><td><code>?file=php://filter/read=convert.base64-encode/resource=../../../etc/passwd</code></td><td>编码读取系统文件</td></tr>
                    <tr><td>Input RCE</td><td><code>POST: ?file=php://input</code></td><td>POST 体作为代码执行</td></tr>
                    <tr><td>Data RCE</td><td><code>?file=data://text/plain,<?php echo 1;?></code></td><td>URI 内嵌代码执行</td></tr>
                </tbody>
            </table>
        </div>
    </main>
</body>
</html>
