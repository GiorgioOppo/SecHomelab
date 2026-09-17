<?php
App::uses('AppShell', 'Console/Command');
App::uses('EnvSetting', 'Tools');

/** Local administrative helper. Receive credentials only through stdin JSON. */
class GreyNoiseSetupShell extends AppShell
{
    public $uses = ['User', 'Feed', 'Event', 'Server', 'Log'];

    const FEED_NAME = 'GreyNoise malicious IPs (last 24h, max 10000)';
    const FEED_URL = '/var/www/MISP/app/files/feeds/greynoise-malicious.txt';

    public function main()
    {
        ini_set('display_errors', '0');
        $stage = 'input';
        try {
            $input = json_decode(stream_get_contents(STDIN), true, 32, JSON_THROW_ON_ERROR);
            if (!is_array($input) || empty($input['email']) || !is_string($input['email'])) {
                throw new RuntimeException('Invalid input');
            }
            $stage = 'user';
            $userRow = $this->User->find('first', [
                'conditions' => ['User.email' => strtolower($input['email'])],
                'fields' => ['User.id'], 'recursive' => -1,
            ]);
            if (empty($userRow)) {
                throw new RuntimeException('User not found');
            }
            $user = $this->User->getAuthUser($userRow['User']['id']);
            if (empty($user['Role']['perm_site_admin'])) {
                throw new RuntimeException('Site administrator required');
            }
            Configure::write('CurrentUserId', $user['id']);
            $mode = $input['mode'] ?? '';

            if ($mode === 'settings') {
                $stage = 'settings_preflight';
                $keyName = 'Plugin.Enrichment_greynoise_api_key';
                $enabledName = 'Plugin.Enrichment_greynoise_enabled';
                if (!isset($input['api_key']) || !is_string($input['api_key']) || trim($input['api_key']) === '') {
                    throw new RuntimeException('API key required');
                }
                if (array_key_exists('enabled', $input) && !is_bool($input['enabled'])) {
                    throw new RuntimeException('Enabled must be boolean');
                }
                // MISP 2.5.46 does not redact names containing "api_key" in its
                // Server setting audit or SystemSetting DB audit. This helper is
                // deliberately limited to the deployed file-backed configuration.
                if (Configure::read('MISP.system_setting_db')) {
                    throw new RuntimeException('Database-backed settings not supported');
                }
                $values = [$keyName => trim($input['api_key'])];
                if (array_key_exists('enabled', $input)) {
                    $values[$enabledName] = $input['enabled'];
                }
                $definitions = [];
                foreach ($values as $name => $value) {
                    $definition = $this->Server->getSettingData($name, false);
                    if (!$definition || EnvSetting::isSetViaEnv($name)
                        || isset($definition['beforeHook']) || isset($definition['afterHook'])) {
                        throw new RuntimeException('Unsupported setting');
                    }
                    $expectedTest = $name === $keyName ? 'testForEmpty' : 'testBool';
                    if (($definition['test'] ?? null) !== $expectedTest
                        || $this->Server->{$expectedTest}($value) !== true) {
                        throw new RuntimeException('Setting validation failed');
                    }
                    $definitions[$name] = $definition;
                }
                if (!is_writable(APP . 'Config/config.php')) {
                    throw new RuntimeException('Configuration is not writable');
                }
                $stage = 'settings_key';
                // Use the native atomic config writer, then a manually redacted
                // audit record. Admin setSetting echoes the key and the higher
                // level serverSettingsEditValue would record it in plaintext.
                if (!$this->Server->serverSettingsSaveValue($keyName, $values[$keyName])) {
                    throw new RuntimeException('Key save failed');
                }
                $this->Log->createLogEntry($user, 'serverSettingsEdit', 'Server', 0,
                    'Server setting changed', [$keyName => ['*****', '*****']]);
                if (array_key_exists($enabledName, $values)) {
                    $stage = 'settings_enabled';
                    $result = $this->Server->serverSettingsEditValue(
                        $user, $definitions[$enabledName], $values[$enabledName], false, true
                    );
                    if ($result !== true) {
                        throw new RuntimeException('Module enable setting failed');
                    }
                }
                $stage = 'settings_verify';
                $saved = (static function ($path) {
                    $config = [];
                    require $path;
                    return $config;
                })(APP . 'Config/config.php');
                $storedKey = Hash::get($saved, $keyName);
                $matches = is_string($storedKey) && hash_equals($values[$keyName], $storedKey);
                $enabled = (bool)Hash::get($saved, $enabledName, false);
                if (!$matches || (array_key_exists($enabledName, $values) && $enabled !== $values[$enabledName])) {
                    throw new RuntimeException('Settings read-back failed');
                }
                $output = ['ok' => true, 'key_matches' => $matches, 'enabled' => $enabled,
                    'enabled_updated' => array_key_exists($enabledName, $values)];
                unset($storedKey, $saved, $values, $input['api_key']);
            } elseif ($mode === 'configure') {
                $stage = 'feed_preflight';
                if (Configure::read('Security.disable_local_feed_access')) {
                    throw new RuntimeException('Local feed access is disabled');
                }
                if (!is_file(self::FEED_URL) || !is_readable(self::FEED_URL)) {
                    throw new RuntimeException('Local feed file is not readable');
                }
                $existing = $this->Feed->find('all', [
                    'conditions' => ['Feed.name' => self::FEED_NAME, 'Feed.provider' => 'GreyNoise', 'Feed.url' => self::FEED_URL],
                    'fields' => ['Feed.id', 'Feed.event_id'], 'recursive' => -1, 'limit' => 2,
                ]);
                if (count($existing) > 1) {
                    throw new RuntimeException('Ambiguous feed');
                }
                $data = [
                    'name' => self::FEED_NAME, 'provider' => 'GreyNoise', 'url' => self::FEED_URL,
                    'headers' => '', 'input_source' => 'local', 'source_format' => 'freetext',
                    'enabled' => false, 'caching_enabled' => false, 'lookup_visible' => false,
                    'fixed_event' => true, 'event_id' => 0, 'publish' => false, 'delta_merge' => true,
                    'override_ids' => true, 'distribution' => 0, 'sharing_group_id' => 0,
                    'tag_id' => 0, 'tag_collection_id' => 0, 'default' => false,
                    'delete_local_file' => false, 'lock_events' => false, 'orgc_id' => $user['org_id'],
                    'settings' => '{}',
                ];
                $created = empty($existing);
                if (!$created) {
                    $data['id'] = $existing[0]['Feed']['id'];
                    $data['event_id'] = $existing[0]['Feed']['event_id'];
                    if ($data['event_id']) {
                        $event = $this->Event->find('first', [
                            'conditions' => ['Event.id' => $data['event_id']],
                            'fields' => ['Event.id', 'Event.org_id', 'Event.distribution', 'Event.published'],
                            'recursive' => -1,
                        ]);
                        if (empty($event) || (int)$event['Event']['org_id'] !== (int)$user['org_id']
                            || (int)$event['Event']['distribution'] !== 0 || $event['Event']['published']) {
                            throw new RuntimeException('Existing event is unsuitable');
                        }
                    }
                } else {
                    $this->Feed->create();
                }
                $stage = 'configure';
                if (!$this->Feed->save(['Feed' => $data], true, array_keys($data))) {
                    throw new RuntimeException('Feed save failed');
                }
                $output = ['ok' => true, 'feed_id' => (int)$this->Feed->id,
                    'user_id' => (int)$user['id'], 'event_id' => (int)$data['event_id'], 'created' => $created];
            } elseif ($mode === 'status' || $mode === 'enable' || $mode === 'disable') {
                $stage = $mode;
                if (empty($input['feed_id']) || !ctype_digit((string)$input['feed_id'])) {
                    throw new RuntimeException('Invalid feed ID');
                }
                $feed = $this->Feed->find('first', [
                    'conditions' => ['Feed.id' => $input['feed_id'], 'Feed.provider' => 'GreyNoise',
                        'Feed.name' => self::FEED_NAME, 'Feed.url' => self::FEED_URL],
                    'fields' => ['Feed.id', 'Feed.event_id', 'Feed.enabled'], 'recursive' => -1,
                ]);
                if (empty($feed)) {
                    throw new RuntimeException('Feed not found');
                }
                if ($mode === 'enable' || $mode === 'disable') {
                    $this->Feed->id = $feed['Feed']['id'];
                    if (!$this->Feed->saveField('enabled', $mode === 'enable')) {
                        throw new RuntimeException('Feed state change failed');
                    }
                    $feed['Feed']['enabled'] = $mode === 'enable';
                }
                $output = ['ok' => true, 'feed_id' => (int)$feed['Feed']['id'],
                    'user_id' => (int)$user['id'], 'event_id' => (int)$feed['Feed']['event_id'],
                    'enabled' => (bool)$feed['Feed']['enabled']];
                if ($output['event_id']) {
                    $event = $this->Event->find('first', [
                        'conditions' => ['Event.id' => $output['event_id']],
                        'fields' => ['Event.id', 'Event.distribution', 'Event.published', 'Event.attribute_count'],
                        'recursive' => -1,
                    ]);
                    if (empty($event)) {
                        throw new RuntimeException('Event not found');
                    }
                    $conditions = ['Attribute.event_id' => $output['event_id'], 'Attribute.deleted' => 0];
                    $output['attribute_count'] = (int)$this->Event->Attribute->find('count', ['conditions' => $conditions, 'recursive' => -1]);
                    $output['ip_dst_count'] = (int)$this->Event->Attribute->find('count', [
                        'conditions' => $conditions + ['Attribute.type' => 'ip-dst'], 'recursive' => -1]);
                    $output['to_ids_count'] = (int)$this->Event->Attribute->find('count', [
                        'conditions' => $conditions + ['Attribute.to_ids' => 1], 'recursive' => -1]);
                    $output['distribution'] = (int)$event['Event']['distribution'];
                    $output['published'] = (bool)$event['Event']['published'];
                    $output['stored_attribute_count'] = (int)$event['Event']['attribute_count'];
                }
            } else {
                throw new RuntimeException('Invalid mode');
            }
            echo 'GREYNOISE_RESULT=' . json_encode($output, JSON_UNESCAPED_SLASHES) . PHP_EOL;
        } catch (Throwable $error) {
            // Never print exceptions, validation errors or payloads containing credentials.
            echo 'GREYNOISE_RESULT=' . json_encode(['ok' => false, 'error' => 'Operation failed', 'stage' => $stage]) . PHP_EOL;
            exit(1);
        }
    }
}
