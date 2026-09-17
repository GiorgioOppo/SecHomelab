<?php
App::uses('AppShell', 'Console/Command');

/** Existing-feed refresh helper. Secrets arrive on stdin and are never saved or printed. */
class AbuseipdbSyncShell extends AppShell
{
    public $uses = ['User', 'Feed', 'Event'];
    private const NAME = 'AbuseIPDB blacklist (confidence 100)';
    private const URL = 'https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=100&limit=10000&plaintext';

    public function main()
    {
        ini_set('display_errors', '0');
        try {
            $input = json_decode(stream_get_contents(STDIN), true, 32, JSON_THROW_ON_ERROR);
            if (!is_array($input) || empty($input['email'])) {
                throw new RuntimeException('Invalid input');
            }
            $row = $this->User->find('first', [
                'conditions' => ['User.email' => strtolower($input['email'])],
                'fields' => ['User.id'], 'recursive' => -1,
            ]);
            if (!$row) {
                throw new RuntimeException('User not found');
            }
            $user = $this->User->getAuthUser($row['User']['id']);
            if (empty($user['Role']['perm_site_admin'])) {
                throw new RuntimeException('Site administrator required');
            }
            Configure::write('CurrentUserId', $user['id']);
            $mode = $input['mode'] ?? '';
            if (!in_array($mode, ['inspect', 'enable', 'status', 'disable'], true)) {
                throw new RuntimeException('Invalid mode');
            }
            $conditions = ['Feed.name' => self::NAME, 'Feed.provider' => 'AbuseIPDB', 'Feed.url' => self::URL];
            if ($mode !== 'inspect') {
                if (empty($input['feed_id']) || !ctype_digit((string)$input['feed_id'])) {
                    throw new RuntimeException('Invalid feed ID');
                }
                $conditions['Feed.id'] = $input['feed_id'];
            }
            $rows = $this->Feed->find('all', [
                'conditions' => $conditions, 'recursive' => -1, 'limit' => 2,
            ]);
            if (count($rows) !== 1) {
                throw new RuntimeException('Missing or ambiguous existing feed');
            }
            $feed = $rows[0]['Feed'];
            if ($mode === 'inspect') {
                $expectedHeaders = 'Key: ' . ($input['api_key'] ?? '') . "\nAccept: text/plain";
                if (empty($input['api_key']) || !hash_equals($expectedHeaders, $feed['headers'])) {
                    throw new RuntimeException('Stored feed key differs from local configuration');
                }
            }
            if ($mode !== 'disable') {
                if ($feed['input_source'] !== 'network' || $feed['source_format'] !== 'freetext'
                    || !$feed['fixed_event'] || !$feed['delta_merge'] || !$feed['override_ids']
                    || $feed['publish'] || (int)$feed['distribution'] !== 0
                    || empty($feed['event_id'])) {
                    throw new RuntimeException('Unexpected feed settings');
                }
                $event = $this->Event->find('first', [
                    'conditions' => ['Event.id' => $feed['event_id']],
                    'fields' => ['Event.id', 'Event.org_id', 'Event.distribution', 'Event.published'],
                    'recursive' => -1,
                ]);
                if (empty($event) || (int)$event['Event']['org_id'] !== (int)$user['org_id']
                    || (int)$event['Event']['distribution'] !== 0 || $event['Event']['published']) {
                    throw new RuntimeException('Existing event is unsuitable');
                }
            }
            if ($mode === 'enable' || $mode === 'disable') {
                // Clear the read model so this save contains only id and enabled,
                // and can never audit the credential-bearing headers field.
                $this->Feed->clear();
                $this->Feed->id = $feed['id'];
                if (!$this->Feed->saveField('enabled', $mode === 'enable')) {
                    throw new RuntimeException('Could not change feed enabled state');
                }
                $feed['enabled'] = $mode === 'enable';
            }
            $output = ['ok' => true, 'feed_id' => (int)$feed['id'], 'user_id' => (int)$user['id'],
                'event_id' => (int)$feed['event_id'], 'enabled' => (bool)$feed['enabled']];
            if ($mode === 'status') {
                $conditions = ['Attribute.event_id' => $feed['event_id'], 'Attribute.deleted' => 0];
                $output['attribute_count'] = (int)$this->Event->Attribute->find('count', [
                    'conditions' => $conditions, 'recursive' => -1]);
                $output['ip_dst_count'] = (int)$this->Event->Attribute->find('count', [
                    'conditions' => $conditions + ['Attribute.type' => 'ip-dst'], 'recursive' => -1]);
                $output['to_ids_count'] = (int)$this->Event->Attribute->find('count', [
                    'conditions' => $conditions + ['Attribute.to_ids' => 1], 'recursive' => -1]);
                $output['distribution'] = (int)$event['Event']['distribution'];
                $output['published'] = (bool)$event['Event']['published'];
            }
            echo 'ABUSEIPDB_SYNC_RESULT=' . json_encode($output) . PHP_EOL;
        } catch (Throwable $error) {
            // Neither exception text nor validation data is safe to forward.
            echo 'ABUSEIPDB_SYNC_RESULT=' . json_encode(['ok' => false]) . PHP_EOL;
            exit(1);
        }
    }
}
