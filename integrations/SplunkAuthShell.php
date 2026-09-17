<?php
App::uses('AppShell', 'Console/Command');

/**
 * Provision only the dedicated Splunk reader through MISP's native models.
 * JSON stdin: {"mode":"configure", "email":"site-admin", "api_key":"optional"}.
 * The SPLUNK_AUTH_RESULT record can contain a newly created secret. Capture it
 * in the calling process, persist privately, and never forward it to a log.
 */
class SplunkAuthShell extends AppShell
{
    public $uses = ['User', 'Role', 'AuthKey'];
    const USER_EMAIL = 'splunk@localhost.test';
    const ROLE_NAME = 'Splunk read-only API';
    const KEY_COMMENT = 'Splunk MISP42 read-only integration';

    private function isReadOnlyRole(array $role)
    {
        if (empty($role['perm_auth'])) {
            return false;
        }
        foreach ($role as $name => $value) {
            if (strpos($name, 'perm_') === 0 && $name !== 'perm_auth' && $value) {
                return false;
            }
        }
        return true;
    }

    public function main()
    {
        ini_set('display_errors', '0');
        $stage = 'input';
        try {
            $input = json_decode(stream_get_contents(STDIN), true, 32, JSON_THROW_ON_ERROR);
            if (!is_array($input) || ($input['mode'] ?? '') !== 'configure'
                || !is_string($input['email'] ?? null) || $input['email'] === '') {
                throw new RuntimeException('Invalid input');
            }
            $key = $input['api_key'] ?? null;
            if ($key !== null && (!is_string($key) || !preg_match('/^[A-Za-z0-9]{40}$/D', $key))) {
                throw new RuntimeException('Invalid key');
            }
            $stage = 'admin';
            $row = $this->User->find('first', [
                'conditions' => ['User.email' => strtolower($input['email'])],
                'fields' => ['User.id'], 'recursive' => -1,
            ]);
            $admin = empty($row) ? false : $this->User->getAuthUser($row['User']['id']);
            if (!$admin || empty($admin['Role']['perm_site_admin']) || !empty($admin['disabled'])) {
                throw new RuntimeException('Active site administrator required');
            }
            if (!Configure::read('Security.advanced_authkeys')) {
                throw new RuntimeException('Advanced authentication keys required');
            }
            Configure::write('CurrentUserId', $admin['id']);

            $stage = 'user_preflight';
            $rows = $this->User->find('all', [
                'conditions' => ['User.email' => self::USER_EMAIL],
                'fields' => ['User.id', 'User.org_id', 'User.role_id', 'User.disabled'],
                'recursive' => -1, 'limit' => 2,
            ]);
            if (count($rows) > 1) {
                throw new RuntimeException('Ambiguous user');
            }
            $userCreated = empty($rows);
            $roleCreated = false;
            if (!$userCreated) {
                $user = $rows[0]['User'];
                $roleRow = $this->Role->find('first', [
                    'conditions' => ['Role.id' => $user['role_id']], 'recursive' => -1,
                ]);
                if ((int)$user['org_id'] !== (int)$admin['org_id'] || !empty($user['disabled'])
                    || empty($roleRow) || !$this->isReadOnlyRole($roleRow['Role'])) {
                    // Never repurpose, enable, or change permissions of an existing account.
                    throw new RuntimeException('Existing account is unsuitable');
                }
                $role = $roleRow['Role'];
            } else {
                $stage = 'role';
                $role = null;
                foreach ($this->Role->find('all', ['recursive' => -1, 'order' => ['Role.id' => 'ASC']]) as $candidate) {
                    if ($this->isReadOnlyRole($candidate['Role'])) {
                        $role = $candidate['Role'];
                        break;
                    }
                }
                if ($role === null) {
                    if ($this->Role->hasAny(['Role.name' => self::ROLE_NAME])) {
                        throw new RuntimeException('Dedicated role name already has other permissions');
                    }
                    $data = ['name' => self::ROLE_NAME, 'permission' => 0];
                    foreach ($this->Role->schema() as $field => $definition) {
                        if (strpos($field, 'perm_') === 0) {
                            $data[$field] = $field === 'perm_auth' ? 1 : 0;
                        }
                    }
                    $this->Role->create();
                    if (!$this->Role->save(['Role' => $data])) {
                        throw new RuntimeException('Role save failed');
                    }
                    $roleRow = $this->Role->find('first', [
                        'conditions' => ['Role.id' => $this->Role->id], 'recursive' => -1,
                    ]);
                    $role = $roleRow['Role'];
                    $roleCreated = true;
                }
                if (!$this->isReadOnlyRole($role)) {
                    throw new RuntimeException('Role verification failed');
                }
                $stage = 'user_create';
                $this->User->create();
                // The model creates an undisclosed random password. No email is sent.
                $data = [
                    'email' => self::USER_EMAIL, 'org_id' => $admin['org_id'],
                    'role_id' => $role['id'], 'invited_by' => $admin['id'],
                    'enable_password' => false, 'change_pw' => true, 'termsaccepted' => false,
                    'disabled' => false, 'autoalert' => false, 'contactalert' => false,
                ];
                if (!$this->User->save(['User' => $data])) {
                    throw new RuntimeException('User save failed');
                }
                $user = ['id' => $this->User->id, 'role_id' => $role['id'], 'org_id' => $admin['org_id']];
            }

            $stage = 'key_preflight';
            $active = $this->AuthKey->find('all', [
                'conditions' => [
                    'AuthKey.user_id' => $user['id'], 'AuthKey.comment' => self::KEY_COMMENT,
                    'OR' => ['AuthKey.expiration' => 0, 'AuthKey.expiration >' => time()],
                ],
                'fields' => ['AuthKey.id', 'AuthKey.read_only', 'AuthKey.expiration'],
                'recursive' => -1, 'limit' => 2,
            ]);
            if (count($active) > 1) {
                throw new RuntimeException('Ambiguous dedicated key');
            }
            $keyCreated = empty($active);
            if (!$keyCreated) {
                if ($key === null) {
                    $stage = 'existing_key_required';
                    throw new RuntimeException('Existing key must be supplied');
                }
                $authenticated = $this->AuthKey->getAuthUserByAuthKey($key);
                if (!$authenticated || (int)$authenticated['id'] !== (int)$user['id']
                    || (int)$authenticated['authkey_id'] !== (int)$active[0]['AuthKey']['id']
                    || empty($authenticated['authkey_read_only'])) {
                    throw new RuntimeException('Existing key does not match');
                }
            } else {
                if ($key !== null && $this->AuthKey->getAuthUserByAuthKey($key, true)) {
                    // A candidate cannot silently reuse another or an expired credential.
                    throw new RuntimeException('Candidate key already exists');
                }
                $stage = 'key_create';
                $key = $key ?? RandomTool::random_str(true, 40);
                $this->AuthKey->create();
                // Zero follows the instance's configured validity policy (unlimited
                // when no policy is configured). Do not override that policy.
                $data = [
                    'user_id' => $user['id'], 'authkey' => $key, 'read_only' => true,
                    'comment' => self::KEY_COMMENT, 'expiration' => 0, 'allowed_ips' => [],
                ];
                if (!$this->AuthKey->save(['AuthKey' => $data])) {
                    throw new RuntimeException('Key save failed');
                }
                $authenticated = $this->AuthKey->getAuthUserByAuthKey($key);
            }
            $stage = 'verify';
            if (!$authenticated || (int)$authenticated['id'] !== (int)$user['id']
                || empty($authenticated['authkey_read_only']) || !empty($authenticated['disabled'])
                || !$this->isReadOnlyRole($authenticated['Role'])) {
                throw new RuntimeException('Authentication verification failed');
            }
            $result = [
                'ok' => true, 'user_id' => (int)$user['id'], 'email' => self::USER_EMAIL,
                'org_id' => (int)$user['org_id'], 'role_id' => (int)$role['id'],
                'role_created' => $roleCreated, 'user_created' => $userCreated,
                'key_created' => $keyCreated, 'authkey_id' => (int)$authenticated['authkey_id'],
                'expiration' => (int)$authenticated['authkey_expiration'], 'read_only' => true,
            ];
            if ($keyCreated) {
                $result['api_key'] = $key;
            }
            echo 'SPLUNK_AUTH_RESULT=' . json_encode($result, JSON_UNESCAPED_SLASHES) . PHP_EOL;
        } catch (Throwable $error) {
            // Exceptions and validation errors can contain credentials; never echo them.
            echo 'SPLUNK_AUTH_RESULT=' . json_encode(['ok' => false, 'error' => 'Operation failed', 'stage' => $stage]) . PHP_EOL;
            exit(1);
        }
    }
}
