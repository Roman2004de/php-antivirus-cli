<?php

$scanner = $argv[1] ?? dirname(__DIR__) . '/antivirus.php';
$scanner = realpath($scanner);
if ($scanner === false) {
    fwrite(STDERR, "Scanner not found.\n");
    exit(1);
}

$workspace = sys_get_temp_dir() . '/php-antivirus-tests-' . bin2hex(random_bytes(8));
if (!mkdir($workspace, 0700)) {
    exit(1);
}

function expect($condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function runScanner(array $arguments, array $phpOptions = []): array
{
    global $scanner, $workspace;
    $stdout = tmpfile();
    $stderr = tmpfile();
    $command = array_merge([PHP_BINARY], $phpOptions, [$scanner], $arguments);
    $process = proc_open($command, [0 => ['pipe', 'r'], 1 => $stdout, 2 => $stderr], $pipes, $workspace);
    expect(is_resource($process), 'Cannot start the scanner.');
    fclose($pipes[0]);
    $status = proc_close($process);
    rewind($stdout);
    rewind($stderr);
    $output = [stream_get_contents($stdout), stream_get_contents($stderr)];
    fclose($stdout);
    fclose($stderr);
    return [$status, $output[0], $output[1]];
}

function expectStatus(array $result, int $expected): void
{
    expect($result[0] === $expected, "Expected exit $expected, got {$result[0]}.\n{$result[1]}{$result[2]}");
}

function expectReport(array $result, int $expectedStatus, int $scanned, int $threats, int $errors): array
{
    expectStatus($result, $expectedStatus);
    $report = json_decode($result[1], true, 512, JSON_THROW_ON_ERROR);
    expect($report['total_scanned'] === $scanned, 'Unexpected file count: ' . $result[1]);
    expect($report['threats_found'] === $threats, 'Unexpected threat count: ' . $result[1]);
    expect($report['runtime_errors'] === $errors, 'Unexpected error count: ' . $result[1]);
    expect(count($report['infected_files']) === $threats, 'Incorrect infected_files list.');
    return $report['infected_files'];
}

function removeTree(string $path): void
{
    if (!is_link($path) && is_dir($path)) {
        @chmod($path, 0700);
        foreach (new FilesystemIterator($path, FilesystemIterator::SKIP_DOTS) as $entry) {
            removeTree($entry->getPathname());
        }
        rmdir($path);
    } else {
        unlink($path);
    }
}

$marker = "<?php\n// eval(\n";
$cases = [
    'CLI validates arguments and accepts both value syntaxes' => static function (string $dir): void {
        file_put_contents("$dir/clean.txt", 'ordinary text');
        foreach ([[], ['--path'], ['--path='], ["--path=$dir", '--unknown'],
            ["--path=$dir", '--log-mode=typo'], ["--path=$dir", "--path=$dir"],
            ["--path=$dir", '--json-report=1'], ['--path=php://input']] as $arguments) {
            expectStatus(runScanner($arguments), 2);
        }
        expectStatus(runScanner(['--help']), 0);
        $result = runScanner(['--path', "$dir/clean.txt"]);
        expectStatus($result, 0);
        expect(strpos($result[1], 'Files scanned: 1') !== false, 'Short mode hid the summary.');
        expectReport(runScanner(["--path=$dir/missing", '--json-report']), 3, 0, 0, 1);
        if (DIRECTORY_SEPARATOR === '/') {
            $root = runScanner(['--path=/', '--quarantine=/', '--json-report']);
            expectReport($root, 3, 0, 0, 1);
            expect(strpos($root[2], 'must differ') !== false, 'Root path was not recognized.');
        }
    },
    'Recursive scan filters extensions case-insensitively and skips binary headers' => static function (string $dir) use ($marker): void {
        mkdir("$dir/nested");
        file_put_contents("$dir/nested/suspect.PHP", $marker);
        file_put_contents("$dir/ignored.dat", $marker);
        file_put_contents("$dir/empty.php", '');
        file_put_contents("$dir/binary.php", "\x89PNG\r\n\x1a\n" . $marker);
        file_put_contents("$dir/text.php", "\x89PNG text only\n" . $marker);
        $files = expectReport(runScanner(["--path=$dir", '--json-report']), 1, 3, 2, 0);
        expect(in_array(realpath("$dir/nested/suspect.PHP"), $files, true), 'Uppercase PHP file missed.');
        expect(in_array(realpath("$dir/text.php"), $files, true), 'Text was skipped due to a partial binary header.');
        expectReport(runScanner(["--path=$dir/ignored.dat", '--json-report']), 1, 1, 1, 0);
        file_put_contents("$dir/callback.txt", "<?php\n// " . '$_POST["marker"]()' . "\n");
        expectReport(runScanner(["--path=$dir/callback.txt", '--json-report']), 1, 1, 1, 0);
    },
    'An unreadable directory records an error and leaves readable siblings in the scan' => static function (string $dir) use ($marker): void {
        mkdir("$dir/closed");
        file_put_contents("$dir/found.php", $marker);
        chmod("$dir/closed", 0000);
        clearstatcache();
        if (is_readable("$dir/closed")) {
            return;
        }
        expectReport(runScanner(["--path=$dir", '--json-report']), 4, 1, 1, 1);
    },
    'Symbolic links are skipped and quarantine excludes its own directory' => static function (string $dir) use ($marker): void {
        mkdir("$dir/scanned");
        mkdir("$dir/scanned/quarantine");
        file_put_contents("$dir/target.php", $marker);
        file_put_contents("$dir/scanned/quarantine/already.php", $marker);
        file_put_contents("$dir/scanned/clean.txt", 'ordinary text');
        if (function_exists('symlink') && @symlink("$dir/target.php", "$dir/scanned/link.php")) {
            symlink($dir, "$dir/scanned/linked-dir");
            expectReport(runScanner(["--path=$dir/scanned/link.php", '--json-report']), 3, 0, 0, 1);
            expectReport(runScanner(["--path=$dir/scanned/linked-dir/", '--json-report']), 3, 0, 0, 1);
        }
        expectReport(runScanner(["--path=$dir/scanned", "--quarantine=$dir/scanned/quarantine", '--json-report']), 0, 1, 0, 0);
        expect(is_file("$dir/target.php"), 'Found an unexpected change outside the scan root.');
    },
    'Custom regex signatures support BOM, comments, and literal hashes' => static function (string $dir) use ($marker): void {
        file_put_contents("$dir/signatures.txt", "\xef\xbb\xbf# header\n\n~Demo # marker~  # inline # note\n");
        file_put_contents("$dir/match.txt", 'Demo # marker');
        file_put_contents("$dir/other.txt", $marker);
        $args = ["--path=$dir", "--signatures-file=$dir/signatures.txt", '--json-report'];
        $files = expectReport(runScanner($args), 1, 2, 1, 0);
        expect($files === [realpath("$dir/match.txt")], 'Unexpected custom signature match.');
        file_put_contents("$dir/signatures.txt", "~Demo # marker~\n/invalid([\n");
        expectReport(runScanner($args), 4, 2, 1, 1);
        file_put_contents("$dir/signatures.txt", "# empty database\n");
        expectReport(runScanner($args), 3, 0, 0, 1);
        unlink("$dir/signatures.txt");
        expectReport(runScanner($args), 3, 0, 0, 1);
    },
    'A PCRE execution error appears in diagnostics and the JSON report' => static function (string $dir): void {
        file_put_contents("$dir/input.php", "text \xff data");
        file_put_contents("$dir/signatures", "/marker/u\n");
        $result = runScanner(["--path=$dir/input.php", "--signatures-file=$dir/signatures", '--json-report']);
        expectReport($result, 4, 1, 0, 1);
        expect(strpos($result[2], 'PCRE error') !== false, 'Missing PCRE diagnostics.');
    },
    'Streaming detects a marker across two blocks under a low memory limit' => static function (string $dir): void {
        $file = "$dir/large.txt";
        $stream = fopen($file, 'wb');
        expect(ftruncate($stream, 12 * 1024 * 1024), 'Failed to size the test file.');
        fseek($stream, 32768 - 4);
        fwrite($stream, 'boundary-marker');
        fclose($stream);
        file_put_contents("$dir/signatures", '/boundary-marker/' . "\n");
        $result = runScanner(["--path=$file", "--signatures-file=$dir/signatures", '--log-mode=verbose',
            '--json-report'], ['-d', 'memory_limit=8M']);
        expectReport($result, 1, 1, 1, 0);
        expect(strpos($result[2], 'Processing large file') !== false, 'Expecting a streaming scan.');
    },
    'Dry run preserves the source and leaves a missing quarantine untouched' => static function (string $dir) use ($marker): void {
        $file = "$dir/suspect.php";
        $quarantine = "$dir/new/quarantine";
        file_put_contents($file, $marker);
        $result = runScanner(["--path=$file", "--quarantine=$quarantine", '--dry-run', '--json-report']);
        expectReport($result, 1, 1, 1, 0);
        expect(strpos($result[2], '[DRY-RUN]') !== false, 'Dry-run action was not shown.');
        expect(file_get_contents($file) === $marker && !file_exists("$dir/new"), 'Dry run changed the filesystem.');
    },
    'Quarantine retains same-named files and records their original paths and hashes' => static function (string $dir) use ($marker): void {
        mkdir("$dir/a");
        mkdir("$dir/b");
        $files = ["$dir/a/item.php", "$dir/b/item.php"];
        foreach ($files as $file) {
            file_put_contents($file, $marker);
        }
        $quarantine = "$dir/quarantine";
        $result = runScanner(["--path=$dir", "--quarantine=$quarantine", '--json-report']);
        expectReport($result, 1, 2, 2, 0);
        $metadataPaths = glob("$quarantine/*/metadata.json");
        expect(count($metadataPaths) === 2, 'Quarantine entries collided.');
        $originals = [];
        foreach ($metadataPaths as $path) {
            $metadata = json_decode(file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
            expect($metadata['sha256'] === hash('sha256', $marker), 'Incorrect quarantine hash.');
            $payload = realpath(dirname($path)) . DIRECTORY_SEPARATOR . 'payload';
            expect($metadata['quarantined_path'] === $payload, 'Unexpected payload path.');
            expect(file_get_contents($metadata['quarantined_path']) === $marker, 'Quarantined file contents changed.');
            expect($metadata['original_name'] === 'item.php', 'Original name was not preserved.');
            $originals[] = $metadata['original_path'];
        }
        sort($originals);
        $sources = array_map(static function (string $file): string {
            expect(!is_file($file), "Source remained in place: $file");
            return realpath(dirname($file)) . DIRECTORY_SEPARATOR . basename($file);
        }, $files);
        expect($originals === $sources, 'Metadata points to different files.');
    },
    'Quarantine errors take precedence over matches and preserve the source' => static function (string $dir) use ($marker): void {
        $file = "$dir/suspect.php";
        file_put_contents($file, $marker);
        file_put_contents("$dir/blocked", 'existing regular file');
        $args = ["--path=$file", "--quarantine=$dir/blocked", '--json-report'];
        expectReport(runScanner($args), 4, 1, 1, 1);
        expect(file_get_contents($file) === $marker, 'The file changed after quarantine failed.');

        mkdir("$dir/read-only");
        $file = "$dir/read-only/suspect.php";
        file_put_contents($file, $marker);
        chmod("$dir/read-only", 0555);
        clearstatcache();
        if (!is_writable("$dir/read-only")) {
            expectReport(runScanner(["--path=$file", "--quarantine=$dir/quarantine", '--json-report']), 4, 1, 1, 1);
            expect(glob("$dir/quarantine/*") === [], 'A failed move left behind an incomplete quarantine entry.');
            expect(file_get_contents($file) === $marker, 'A failed move removed the source.');
        }
    },
    'The log includes the summary and is excluded from a recursive scan' => static function (string $dir) use ($marker): void {
        file_put_contents("$dir/clean.txt", 'ordinary text');
        file_put_contents("$dir/scanner.txt", $marker);
        $result = runScanner(["--path=$dir", "--log-file=$dir/scanner.txt", '--log-mode=verbose', '--json-report']);
        expectReport($result, 0, 1, 0, 0);
        expect(strpos(file_get_contents("$dir/scanner.txt"), 'Files scanned: 1') !== false, 'Missing log summary.');
        expectReport(runScanner(["--path=$dir/clean.txt", "--log-file=$dir/clean.txt", '--json-report']), 3, 0, 0, 1);
        expect(file_get_contents("$dir/clean.txt") === 'ordinary text', 'Log setup modified the scan target.');
        expectReport(runScanner(["--path=$dir", "--log-file=$dir/no-parent/log", '--json-report']), 3, 0, 0, 1);
    },
    'JSON remains valid for a path containing invalid UTF-8' => static function (string $dir) use ($marker): void {
        if (DIRECTORY_SEPARATOR !== '/') {
            return;
        }
        file_put_contents("$dir/bad-\xff.php", $marker);
        expectReport(runScanner(["--path=$dir", '--json-report']), 1, 1, 1, 0);
    },
];

$failures = 0;
try {
    foreach ($cases as $name => $test) {
        $directory = $workspace . '/' . bin2hex(random_bytes(6));
        mkdir($directory, 0700);
        try {
            $test($directory);
            echo "PASS $name\n";
        } catch (Throwable $error) {
            $failures++;
            fwrite(STDERR, "FAIL $name\n{$error->getMessage()}\n");
        }
    }
} finally {
    removeTree($workspace);
}

echo count($cases) . " tests, $failures failures.\n";
exit($failures > 0 ? 1 : 0);
