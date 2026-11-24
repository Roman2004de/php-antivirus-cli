<?php
/**
 * PHP Antivirus: Command-Line Malware Scanner
 *
 * @author Roman Tarasenko
 * @version 1.0
 * @license MIT
 * @link https://github.com/Roman2004de/php-antivirus-cli
 */

class Antivirus
{
    public const EXIT_CLEAN = 0;
    public const EXIT_THREATS_FOUND = 1;
    public const EXIT_CLI_ERROR = 2;
    public const EXIT_RUNTIME_ERROR = 3;
    public const EXIT_PARTIAL_ERROR = 4;

    private const BLOCK_SIZE = 32768;
    private const OVERLAP_SIZE = 512;
    private const MAX_FILE_SIZE = 104857600;
    private const EXTENSIONS = [
        'php', 'js', 'phtml', 'phtm', 'cgi', 'pl', 'o', 'so', 'py', 'sh',
        'php3', 'php4', 'php5', 'php6', 'php7', 'pht', 'shtml', 'susp',
        'suspected', 'infected', 'vir', 'html', 'htm', 'tpl', 'inc', 'css',
        'txt', 'sql', 'svg', 'htaccess',
    ];
    private const BINARY_HEADERS = [
        "MZ", "\x89PNG\r\n\x1a\n", "\xff\xd8\xff", "PK\x03\x04",
        '%PDF', 'Rar!', 'GIF87a', 'GIF89a', "\x7fELF", 'ID3', "\0\0\0\x18ftyp",
    ];
    private const DEFAULT_SIGNATURES = [
        '/<\s*(script|iframe|object|embed)\b|fromCharCode\s*\(|setTimeout\s*\(|setInterval\s*\(/i',
        '/<\s*form\b[^>]*action\s*=\s*["\'][^"\']*(login|signin|bank|account|paypal|wallet)[^"\']*["\']/i',
        '/\b(eval|assert|base64_decode|system|passthru|proc_open|pcntl_exec|shell_exec|create_function|exec|socket_create|curl_exec|curl_multi_exec|popen|call_user_func|fsockopen|gzuncompress|str_rot13)\s*\(/i',
        '/\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]\r\n]*\]\s*\(/i',
        '/\x75\x6E\x61\x6D\x65\x28\x29\x20\x7B\x20\x7D/i',
        '/file_put_contents\s*\(\s*["\']php:\/\/input["\']\s*,/i',
        '/preg_replace\s*\(\s*[\'"].*\/e[\'"]\s*,/i',
        '/\b(move_uploaded_file|copy)\s*\(\s*\$_FILES\s*\[\s*[\'"].*[\'"]\s*\]\s*\[\s*[\'"]tmp_name[\'"]\s*\]/i',
    ];

    private $logMode;
    private $signaturesFile;
    private $logFile;
    private $quarantinePath;
    private $outputJson;
    private $dryRun;

    private $logHandle;
    private $logPath;
    private $logIdentity;
    private $signaturesPath;
    private $quarantineDirectory;
    private $signatures = [];
    private $infectedFiles = [];
    private $totalScanned = 0;
    private $runtimeErrors = 0;

    public function __construct($logMode, $signaturesFile = null, $logFile = null, $quarantinePath = null, $outputJson = false, $dryRun = false)
    {
        $this->logMode = $logMode;
        $this->logFile = $logFile;
        $this->quarantinePath = $quarantinePath;
        $this->outputJson = $outputJson;
        $this->dryRun = $dryRun;
        $this->signaturesFile = $signaturesFile;
    }

    public function scan(string $path): int
    {
        if (($this->outputJson || ($this->quarantinePath !== null && !$this->dryRun))
            && !function_exists('json_encode')) {
            fwrite(STDERR, 'JSON reports and quarantine require the PHP JSON extension.' . PHP_EOL);
            return self::EXIT_RUNTIME_ERROR;
        }

        $this->totalScanned = 0;
        $this->runtimeErrors = 0;
        $this->infectedFiles = [];
        $this->logPath = null;
        $this->logIdentity = null;
        $this->signaturesPath = null;
        $this->quarantineDirectory = $this->quarantinePath === null
            ? null
            : (realpath($this->quarantinePath) ?: null);

        $root = realpath($path);
        if ($root === false || $this->isLink($path) || (!is_dir($root) && !is_file($root))) {
            $this->addRuntimeError("Scan path must be an existing regular file or directory: $path");
            return $this->showResults(self::EXIT_RUNTIME_ERROR);
        }
        if ($this->samePath($root, $this->quarantineDirectory)) {
            $this->addRuntimeError("Scan path and quarantine directory must differ: $root");
            return $this->showResults(self::EXIT_RUNTIME_ERROR);
        }

        if (!$this->openLog($root)) {
            return $this->showResults(self::EXIT_RUNTIME_ERROR);
        }

        try {
            if (!$this->loadSignatures()) {
                return $this->showResults(self::EXIT_RUNTIME_ERROR);
            }

            $this->log("Starting scan: $root");
            if (is_dir($root)) {
                $this->scanDirectory($root);
            } else {
                $this->checkFile($root);
            }

            if ($this->quarantinePath !== null) {
                foreach ($this->infectedFiles as $file => $identity) {
                    $this->moveToQuarantine($file, $identity);
                }
            }

            return $this->showResults();
        } finally {
            if (is_resource($this->logHandle)) {
                fclose($this->logHandle);
                $this->logHandle = null;
            }
        }
    }

    private function openLog(string $root): bool
    {
        if ($this->logFile === null) {
            return true;
        }

        $existingLog = realpath($this->logFile);
        if ($existingLog !== false) {
            $logStat = @stat($existingLog);
            foreach ([$root, $this->signaturesFile, __FILE__] as $input) {
                if ($input !== null && is_file($input)
                    && ($this->samePath($existingLog, realpath($input) ?: null)
                        || $this->sameFile($logStat, @stat($input)))) {
                    $this->addRuntimeError("Log file overlaps an input file: {$this->logFile}");
                    return false;
                }
            }
        }

        if ($this->isLink($this->logFile) || (file_exists($this->logFile) && !is_file($this->logFile))) {
            $this->addRuntimeError("Log path must be a regular file: {$this->logFile}");
            return false;
        }
        $this->logHandle = @fopen($this->logFile, 'ab');
        if ($this->logHandle === false) {
            $this->addRuntimeError("Cannot open log file: {$this->logFile}");
            return false;
        }

        $this->logPath = realpath($this->logFile) ?: null;
        $this->logIdentity = fstat($this->logHandle);
        return true;
    }

    private function loadSignatures(): bool
    {
        if ($this->signaturesFile === null) {
            $this->signatures = self::DEFAULT_SIGNATURES;
            return true;
        }

        $this->signatures = [];
        $lines = is_file($this->signaturesFile) ? @file($this->signaturesFile, FILE_IGNORE_NEW_LINES) : false;
        if ($lines === false) {
            $this->addRuntimeError("Cannot read signatures file: {$this->signaturesFile}");
            return false;
        }
        $this->signaturesPath = realpath($this->signaturesFile) ?: null;

        foreach ($lines as $offset => $line) {
            if ($offset === 0 && strpos($line, "\xef\xbb\xbf") === 0) {
                $line = substr($line, 3);
            }
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }

            // Try the complete expression first. A space followed by # can be part of a regex.
            if (@preg_match($line, '') !== false) {
                $this->signatures[] = $line;
                continue;
            }

            preg_match_all('/[ \t]+#/', $line, $comments, PREG_OFFSET_CAPTURE);
            foreach ($comments[0] as [, $position]) {
                $pattern = substr($line, 0, $position);
                if (@preg_match($pattern, '') !== false) {
                    $this->signatures[] = $pattern;
                    continue 2;
                }
            }

            $this->addRuntimeError('Invalid signature at line ' . ($offset + 1) . ": {$this->signaturesFile}");
        }

        if ($this->signatures === []) {
            $this->addRuntimeError("No valid signatures in: {$this->signaturesFile}");
            return false;
        }

        return true;
    }

    private function scanDirectory(string $directory): void
    {
        $this->log("Scanning directory: $directory");
        try {
            foreach (new FilesystemIterator($directory, FilesystemIterator::SKIP_DOTS) as $entry) {
                $path = $entry->getPathname();
                if ($entry->isLink() || $this->samePath($path, $this->quarantineDirectory)) {
                    continue;
                }

                if ($entry->isDir()) {
                    $this->scanDirectory($path);
                } elseif (!$this->samePath($path, $this->signaturesPath)
                    && in_array(strtolower($entry->getExtension()), self::EXTENSIONS, true)) {
                    $this->checkFile($path);
                }
            }
        } catch (RuntimeException $error) {
            $this->addRuntimeError("Cannot scan directory $directory: " . $error->getMessage());
        }
    }

    private function checkFile(string $file): void
    {
        if ($this->samePath($file, $this->logPath)) {
            return;
        }
        $this->log("Checking: $file");

        clearstatcache(true, $file);
        $identity = @lstat($file);
        if (!$this->isRegularFile($identity)) {
            $this->addRuntimeError("Cannot scan non-regular file: $file");
            return;
        }
        if ($this->sameFile($identity, $this->logIdentity)) {
            return;
        }

        $handle = @fopen($file, 'rb');
        if ($handle === false) {
            $this->addRuntimeError("Cannot open file: $file");
            return;
        }

        try {
            $openedFile = fstat($handle);
            if (!$this->sameVersion($identity, $openedFile)) {
                $this->addRuntimeError("File changed before scanning: $file");
                return;
            }
            $header = @fread($handle, 8);
            if ($header === false) {
                $this->addRuntimeError("Cannot read file header: $file");
                return;
            }
            foreach (self::BINARY_HEADERS as $signature) {
                if (strpos($header, $signature) === 0) {
                    $this->log("Skipping binary file: $file");
                    return;
                }
            }
            if (!@rewind($handle)) {
                $this->addRuntimeError("Cannot rewind file: $file");
                return;
            }

            $this->totalScanned++;
            $size = $openedFile['size'];
            if ($size > $this->wholeFileLimit()) {
                $this->log("Processing large file: $file");
                $matched = $this->processLargeFile($handle, $file, $size);
            } else {
                $content = @stream_get_contents($handle, $size + 1);
                if ($content === false || strlen($content) !== $size) {
                    $this->addRuntimeError("Could not read the expected file contents: $file");
                    return;
                }
                $failedSignatures = [];
                $matched = $this->matchesSignature($content, $file, $failedSignatures);
            }

            if (!$this->sameVersion($openedFile, fstat($handle))) {
                $this->addRuntimeError("File changed during scanning: $file");
                return;
            }
            if ($matched) {
                $this->infectedFiles[$file] = $openedFile;
                $this->log("Threat detected in: $file", true);
            }
        } finally {
            fclose($handle);
        }
    }

    private function wholeFileLimit(): int
    {
        $setting = strtolower(trim((string) ini_get('memory_limit')));
        if ($setting === '' || $setting === '-1') {
            return self::MAX_FILE_SIZE;
        }

        $units = ['k' => 1024, 'm' => 1048576, 'g' => 1073741824];
        $limit = (float) $setting * ($units[substr($setting, -1)] ?? 1);
        $available = $limit - memory_get_usage(true);
        // Reserve half of the available memory for the scan state and PCRE.
        return (int) max(0, min(self::MAX_FILE_SIZE, $available / 2));
    }

    private function processLargeFile($handle, string $file, int $remaining): bool
    {
        $overlap = '';
        $failedSignatures = [];
        while ($remaining > 0) {
            $chunk = @fread($handle, min(self::BLOCK_SIZE, $remaining));
            if ($chunk === false || $chunk === '') {
                $this->addRuntimeError("Cannot read a block from: $file");
                return false;
            }

            $remaining -= strlen($chunk);
            $buffer = $overlap . $chunk;
            if ($this->matchesSignature($buffer, $file, $failedSignatures)) {
                return true;
            }
            $overlap = substr($buffer, -self::OVERLAP_SIZE);
        }
        return false;
    }

    private function matchesSignature(string $text, string $file, array &$failedSignatures): bool
    {
        foreach ($this->signatures as $index => $signature) {
            $match = @preg_match($signature, $text);
            if ($match === 1) {
                return true;
            }
            if ($match === false && !isset($failedSignatures[$index])) {
                $failedSignatures[$index] = true;
                $this->addRuntimeError('PCRE error ' . preg_last_error() . ' in signature ' . ($index + 1) . ": $file");
            }
        }
        return false;
    }

    private function moveToQuarantine(string $file, array $identity): void
    {
        clearstatcache(true, $file);
        if (!$this->sameVersion($identity, @lstat($file))) {
            $this->addRuntimeError("File changed before quarantine: $file");
            return;
        }
        if ($this->dryRun) {
            $this->log("[DRY-RUN] Would move to quarantine: $file -> {$this->quarantinePath}", true);
            return;
        }

        $hash = @hash_file('sha256', $file);
        if ($hash === false) {
            $this->addRuntimeError("Cannot calculate hash for: $file");
            return;
        }
        $directory = $this->quarantinePath;
        if ($this->isLink($directory)
            || (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory))) {
            $this->addRuntimeError("Cannot create or use quarantine directory: $directory");
            return;
        }
        $directory = realpath($directory);
        if ($directory === false) {
            $this->addRuntimeError("Cannot resolve quarantine directory: {$this->quarantinePath}");
            return;
        }

        try {
            $entry = $directory . DIRECTORY_SEPARATOR . date('Ymd_His') . '_' . bin2hex(random_bytes(8));
        } catch (Exception $error) {
            $this->addRuntimeError("Cannot generate quarantine entry name: $file");
            return;
        }
        if (!@mkdir($entry, 0700)) {
            $this->addRuntimeError("Cannot create quarantine entry: $entry");
            return;
        }

        $destination = $entry . DIRECTORY_SEPARATOR . 'payload';
        $metadataPath = $entry . DIRECTORY_SEPARATOR . 'metadata.json';
        $metadata = json_encode([
            'original_path' => $file,
            'quarantined_path' => $destination,
            'sha256' => $hash,
            'quarantined_at' => date('c'),
            'original_name' => basename($file),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);

        if ($metadata === false || @file_put_contents($metadataPath, $metadata) !== strlen($metadata)) {
            $this->addRuntimeError("Cannot write quarantine metadata: $metadataPath");
        } else {
            clearstatcache(true, $file);
            if (!$this->sameVersion($identity, @lstat($file))) {
                $this->addRuntimeError("File changed before quarantine: $file");
            } elseif ($this->relocateFile($file, $destination, $identity, $hash)) {
                $this->log("Moved to quarantine: $destination", true);
                return;
            } else {
                $this->addRuntimeError("Cannot move file to quarantine: $file");
            }
        }

        if ((file_exists($destination) && !@unlink($destination))
            || (file_exists($metadataPath) && !@unlink($metadataPath))
            || !@rmdir($entry)) {
            $this->addRuntimeError("Cannot remove incomplete quarantine entry: $entry");
        }
    }

    private function relocateFile(string $file, string $destination, array $identity, string $hash): bool
    {
        $targetDirectory = @stat(dirname($destination));
        if ($targetDirectory === false) {
            return false;
        }
        if ($identity['dev'] === $targetDirectory['dev']) {
            return @rename($file, $destination);
        }

        // Across filesystems PHP's rename may report success even when source removal fails.
        if (!@copy($file, $destination) || @hash_file('sha256', $destination) !== $hash) {
            return false;
        }
        clearstatcache(true, $file);
        return $this->sameVersion($identity, @lstat($file)) && @unlink($file);
    }

    private function isRegularFile($stat): bool
    {
        return is_array($stat) && ($stat['mode'] & 0170000) === 0100000;
    }

    private function isLink(string $path): bool
    {
        return is_link(rtrim($path, DIRECTORY_SEPARATOR === '\\' ? '/\\' : '/'));
    }

    private function sameVersion($before, $after): bool
    {
        return $this->isRegularFile($before) && $this->isRegularFile($after)
            && $before['dev'] === $after['dev'] && $before['ino'] === $after['ino']
            && $before['size'] === $after['size'] && $before['mtime'] === $after['mtime']
            && $before['ctime'] === $after['ctime'];
    }

    private function sameFile($first, $second): bool
    {
        return is_array($first) && is_array($second) && $first['ino'] !== 0
            && $first['dev'] === $second['dev'] && $first['ino'] === $second['ino'];
    }

    private function samePath(string $first, ?string $second): bool
    {
        if ($second === null) {
            return false;
        }
        return DIRECTORY_SEPARATOR === '\\' ? strcasecmp($first, $second) === 0 : $first === $second;
    }

    private function showResults(?int $failure = null): int
    {
        $threatCount = count($this->infectedFiles);
        $summary = "Scan complete. Files scanned: {$this->totalScanned}. Threats found: $threatCount.";
        $this->writeLog(self::logLine($summary . " Runtime errors: {$this->runtimeErrors}."));

        if ($this->outputJson) {
            echo json_encode([
                'total_scanned' => $this->totalScanned,
                'threats_found' => $threatCount,
                'runtime_errors' => $this->runtimeErrors,
                'infected_files' => array_keys($this->infectedFiles),
            ], JSON_PRETTY_PRINT | JSON_INVALID_UTF8_SUBSTITUTE) . PHP_EOL;
        } else {
            echo $summary . " Runtime errors: {$this->runtimeErrors}." . PHP_EOL;
        }

        if ($failure !== null) {
            return $failure;
        }
        if ($this->runtimeErrors > 0) {
            return self::EXIT_PARTIAL_ERROR;
        }
        return $threatCount > 0 ? self::EXIT_THREATS_FOUND : self::EXIT_CLEAN;
    }

    private function addRuntimeError(string $message): void
    {
        $this->runtimeErrors++;
        $this->log($message, true);
    }

    private function log(string $message, bool $important = false): void
    {
        if ($this->logMode !== 'verbose' && !$important) {
            return;
        }

        $message = self::logLine($message);
        fwrite(STDERR, $message);
        $this->writeLog($message);
    }

    private function writeLog(string $line): void
    {
        if (!is_resource($this->logHandle)) {
            return;
        }

        if (!@flock($this->logHandle, LOCK_EX)) {
            $written = false;
        } else {
            $written = @fwrite($this->logHandle, $line);
            @flock($this->logHandle, LOCK_UN);
        }
        if ($written !== strlen($line)) {
            fclose($this->logHandle);
            $this->logHandle = null;
            $this->runtimeErrors++;
            fwrite(STDERR, self::logLine("Cannot write log file: {$this->logFile}"));
        }
    }

    private static function logLine(string $message): string
    {
        $message = preg_replace_callback('/[\x00-\x1f\x7f]/', static function (array $match): string {
            return sprintf('\\x%02x', ord($match[0]));
        }, $message);
        return date('[Y-m-d H:i:s] ') . $message . PHP_EOL;
    }
}

function antivirusMain(array $arguments): int
{
    $usage = 'Usage: php antivirus.php --path=PATH [--signatures-file=FILE] [--log-mode=short|verbose]'
        . ' [--log-file=FILE] [--quarantine=DIR] [--dry-run] [--json-report]' . PHP_EOL;
    if ($arguments === ['--help'] || $arguments === ['-h']) {
        echo $usage;
        return Antivirus::EXIT_CLEAN;
    }

    $valueOptions = ['path', 'signatures-file', 'log-mode', 'log-file', 'quarantine'];
    $flags = ['dry-run', 'json-report'];
    $options = [];
    $count = count($arguments);
    for ($index = 0; $index < $count; $index++) {
        $argument = $arguments[$index];
        if (strpos($argument, '--') !== 0) {
            fwrite(STDERR, $usage);
            return Antivirus::EXIT_CLI_ERROR;
        }

        [$name, $value] = array_pad(explode('=', substr($argument, 2), 2), 2, null);
        if (isset($options[$name])) {
            fwrite(STDERR, 'Each option can be specified only once.' . PHP_EOL . $usage);
            return Antivirus::EXIT_CLI_ERROR;
        }

        if (in_array($name, $valueOptions, true)) {
            if ($value === null && isset($arguments[$index + 1]) && strpos($arguments[$index + 1], '--') !== 0) {
                $value = $arguments[++$index];
            }
            if ($value === null || $value === '' || strpos($value, "\0") !== false) {
                fwrite(STDERR, 'An option is missing its value.' . PHP_EOL . $usage);
                return Antivirus::EXIT_CLI_ERROR;
            }
            $options[$name] = $value;
        } elseif ($value === null && in_array($name, $flags, true)) {
            $options[$name] = true;
        } else {
            fwrite(STDERR, 'Unknown option or unexpected value.' . PHP_EOL . $usage);
            return Antivirus::EXIT_CLI_ERROR;
        }
    }

    $logMode = $options['log-mode'] ?? 'short';
    if (!isset($options['path']) || !in_array($logMode, ['short', 'verbose'], true)) {
        fwrite(STDERR, $usage);
        return Antivirus::EXIT_CLI_ERROR;
    }
    foreach (['path', 'log-file', 'signatures-file', 'quarantine'] as $name) {
        if (isset($options[$name]) && preg_match('~^[a-z][a-z0-9+.-]*://~i', $options[$name])) {
            fwrite(STDERR, 'Options that take paths require local filesystem paths.' . PHP_EOL);
            return Antivirus::EXIT_CLI_ERROR;
        }
    }

    $antivirus = new Antivirus(
        $logMode,
        $options['signatures-file'] ?? null,
        $options['log-file'] ?? null,
        $options['quarantine'] ?? null,
        isset($options['json-report']),
        isset($options['dry-run'])
    );
    return $antivirus->scan($options['path']);
}

if (PHP_SAPI === 'cli' && realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    exit(antivirusMain(array_slice($argv, 1)));
}
