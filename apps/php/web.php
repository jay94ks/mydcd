<?php
declare(strict_types=1);

$requestStarted = hrtime(true);

// Real PHP/PDO application consumed by the two-node Compose scenario.
// Credentials come only from the engine's read-only Secret projection.
function timing(string $stage, int $started, ?PDOException $failure = null): void {
    $ms = (hrtime(true) - $started) / 1000000;
    if (getenv('SFC_DNS_TIMING') === '1' && ($ms >= 100 || $failure !== null)) {
        $event = ['event' => 'app-stage', 'stage' => $stage, 'elapsed_ms' => round($ms, 3), 'pid' => getmypid(),
                  'request_started' => $GLOBALS['requestStarted']];
        if ($failure !== null) {
            $event['sqlstate'] = (string) ($failure->errorInfo[0] ?? $failure->getCode());
            $event['driver_code'] = (int) ($failure->errorInfo[1] ?? 0);
        }
        // No exception text, credentials, SQL values or request payloads.
        error_log(json_encode($event));
    }
}

function sqlProgress(string $stage): void {
    if (getenv('SFC_DNS_TIMING') === '1') {
        error_log(json_encode(['event' => 'sql-progress', 'stage' => $stage, 'pid' => getmypid(),
            'request_started' => $GLOBALS['requestStarted'],
            'method' => in_array($_SERVER['REQUEST_METHOD'] ?? '', ['GET', 'POST', 'PUT', 'DELETE'], true) ? $_SERVER['REQUEST_METHOD'] : 'other',
            'elapsed_ms' => round((hrtime(true) - $GLOBALS['requestStarted']) / 1000000, 3)]));
    }
}

function database(): PDO {
    $password = file_get_contents('/run/secrets/db-password');
    if ($password === false || $password === '') {
        throw new RuntimeException('protected input unavailable');
    }
    $host = getenv('DB_HOST');
    if ($host === false || (filter_var($host, FILTER_VALIDATE_IP) === false &&
        preg_match('/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.?$/D', $host) !== 1)) {
        throw new RuntimeException('explicit DB address or DNS name required');
    }
    $started = hrtime(true);
    try {
        $pdo = new PDO("mysql:host={$host};port=3306;dbname=sfc;charset=utf8mb4", 'sfc', $password,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 2,
             PDO::ATTR_EMULATE_PREPARES => false]);
    } catch (PDOException $failure) {
        timing('pdo-connect', $started, $failure);
        throw $failure;
    }
    timing('pdo-connect', $started);
    return $pdo;
}

try {
    // Explicit DNS-only boundary input; the normal SQL scenario never sets it.
    // This consumes libc/search in the same PHP HTTP/CLI runtime, without
    // hiding a SQL failure as Ready or requiring a MySQL image initialization.
    if (getenv('SFC_DNS_FIXTURE') === '1') {
        $host = getenv('DB_HOST');
        $address = gethostbyname($host);
        if ($address !== getenv('SFC_DNS_EXPECTED')) {
            http_response_code(503);
            if (PHP_SAPI === 'cli') { exit(1); }
        }
        header('Content-Type: application/json');
        echo json_encode(['driver' => 'dns', 'ready' => $address === getenv('SFC_DNS_EXPECTED'),
            'db_host' => $host, 'db_address' => $address]);
        exit(0);
    }
    $path = PHP_SAPI === 'cli' ? '' : parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    if ($path === '/dns') {
        // Resolver diagnostics have no SQL dependency. SQL readiness and CRUD
        // still connect through the declared DB name on their own paths.
        $started = hrtime(true);
        $address = gethostbyname(getenv('DB_HOST'));
        timing('diagnostic-dns', $started);
        header('Content-Type: application/json');
        echo json_encode(['driver' => 'dns', 'db_host' => getenv('DB_HOST'), 'db_address' => $address]);
        exit(0);
    }
    if ($path === '/row') {
        sqlProgress('request-entry');
    }
    $db = database();
    if (PHP_SAPI !== 'cli' && parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) === '/row') {
        sqlProgress('connected');
    }
    if (PHP_SAPI === 'cli') {
        $db->query('SELECT 1')->fetchColumn();
        exit(0);
    }
    header('Content-Type: application/json');
    if ($path === '/readyz') {
        $started = hrtime(true);
        $db->query('SELECT 1 FROM records LIMIT 1')->fetchColumn();
        timing('ready-sql', $started);
        echo json_encode(['ready' => true, 'driver' => $db->getAttribute(PDO::ATTR_DRIVER_NAME),
            'db_host' => getenv('DB_HOST')]);
    } elseif ($path === '/operation') {
        $op = $_GET['id'] ?? '';
        if (!is_string($op) || preg_match('/^[a-zA-Z0-9_-]{1,64}$/D', $op) !== 1) {
            http_response_code(400);
            echo '{"error":"invalid operation"}';
        } else {
            $read = $db->prepare('SELECT result FROM operations WHERE operation_id = ?');
            $read->execute([$op]);
            $result = $read->fetchColumn();
            if ($result === false || $result === null) {
                http_response_code(404);
                echo '{"status":"unobserved"}';
            } else {
                $saved = json_decode($result, true, flags: JSON_THROW_ON_ERROR);
                http_response_code($saved['status']);
                echo json_encode($saved['body']);
            }
        }
    } elseif ($path === '/row') {
        $key = $_GET['key'] ?? '';
        $method = $_SERVER['REQUEST_METHOD'];
        if (!is_string($key) || preg_match('/^[a-zA-Z0-9_-]{1,64}$/D', $key) !== 1) {
            http_response_code(400);
            echo '{"error":"invalid key"}';
        } elseif ($method === 'GET') {
            $read = $db->prepare('SELECT id, value FROM records WHERE id = ?');
            $read->execute([$key]);
            $row = $read->fetch(PDO::FETCH_ASSOC);
            if ($row === false) {
                http_response_code(404);
                echo '{"error":"not found"}';
            } else {
                echo json_encode($row, flags: JSON_THROW_ON_ERROR);
            }
        } elseif (in_array($method, ['POST', 'PUT', 'DELETE'], true)) {
            $op = $_GET['operation'] ?? '';
            $value = file_get_contents('php://input', false, null, 0, 131073);
            if (!is_string($op) || preg_match('/^[a-zA-Z0-9_-]{1,64}$/D', $op) !== 1 ||
                $value === false || strlen($value) > 131072 || preg_match('//u', $value) !== 1 ||
                ($method === 'DELETE' && $value !== '')) {
                http_response_code(400);
                echo '{"error":"invalid operation or value"}';
            } else {
                // Claim, mutation and original result commit in ONE InnoDB
                // transaction. A duplicate operation never repeats its effect.
                $hash = hash('sha256', $method . "\0" . $key . "\0" . $value);
                sqlProgress('begin');
                $db->beginTransaction();
                $claim = $db->prepare('INSERT INTO operations(operation_id,payload_hash) VALUES(?,?) ON DUPLICATE KEY UPDATE operation_id=operation_id');
                $claim->execute([$op, $hash]);
                sqlProgress('claimed');
                $read = $db->prepare('SELECT payload_hash,result FROM operations WHERE operation_id=? FOR UPDATE');
                $read->execute([$op]);
                $original = $read->fetch(PDO::FETCH_ASSOC);
                sqlProgress('original-read');
                if (!hash_equals($original['payload_hash'], $hash)) {
                    $db->rollBack();
                    http_response_code(409);
                    echo '{"error":"operation payload conflict"}';
                } elseif ($original['result'] !== null) {
                    $db->commit();
                    $saved = json_decode($original['result'], true, flags: JSON_THROW_ON_ERROR);
                    http_response_code($saved['status']);
                    echo json_encode($saved['body'], flags: JSON_THROW_ON_ERROR);
                } else {
                    $lookup = $db->prepare('SELECT id FROM records WHERE id=? FOR UPDATE');
                    $lookup->execute([$key]);
                    $exists = $lookup->fetchColumn() !== false;
                    sqlProgress('row-read');
                    $status = 200;
                    $body = ['id' => $key, 'operation' => $op];
                    if ($method === 'POST' && $exists) {
                        $status = 409;
                        $body['error'] = 'already exists';
                    } elseif ($method !== 'POST' && !$exists) {
                        $status = 404;
                        $body['error'] = 'not found';
                    } elseif ($method === 'DELETE') {
                        $write = $db->prepare('DELETE FROM records WHERE id=?');
                        $write->execute([$key]);
                        $body['deleted'] = true;
                    } else {
                        $query = $method === 'POST' ? 'INSERT INTO records(value,id) VALUES(?,?)' : 'UPDATE records SET value=? WHERE id=?';
                        $write = $db->prepare($query);
                        $write->execute([$value, $key]);
                        $body['value'] = $value;
                    }
                    sqlProgress('mutation-written');
                    $save = $db->prepare('UPDATE operations SET result=? WHERE operation_id=?');
                    $save->execute([json_encode(['status' => $status, 'body' => $body], flags: JSON_THROW_ON_ERROR), $op]);
                    sqlProgress('result-stored');
                    $db->commit();
                    sqlProgress('committed');
                    // No response claims success before commit completes.
                    http_response_code($status);
                    echo json_encode($body, flags: JSON_THROW_ON_ERROR);
                }
            }
        } else {
            http_response_code(405);
            echo '{"error":"unsupported method"}';
        }
    } else {
        http_response_code(404);
        echo '{"error":"not found"}';
    }
} catch (Throwable $error) {
    // PDO errors may contain connection/credential context. Keep them private.
    if (PHP_SAPI === 'cli') { exit(1); }
    if (isset($db) && $db->inTransaction()) {
        try { $db->rollBack(); } catch (Throwable $rollbackError) { $db = null; }
    }
    http_response_code(503);
    echo '{"status":"unknown"}';
}
