<?php
/**
 * postbox -- the draft/outbox model.
 *
 * A draft lives in the client's `draft` cookie as base64(serialize($draft)), so
 * an unsent message survives a browser restart without costing us a session
 * row. Everybody knows that means the blob is attacker-controlled, which is
 * why DraftMessage refuses to carry any state across the boundary.
 */

/*
 * The spool and the audit log live OUTSIDE the document root. Both of them
 * echo back whatever a draft carried, so they are not something Apache should
 * ever serve directly: spool.php is the only reader.
 */
define('SPOOL_DIR',  '/var/postbox');
define('SPOOL_FILE', SPOOL_DIR . '/spool.txt');
define('AUDIT_LOG',  SPOOL_DIR . '/audit.log');

/** A file queued for delivery. Rendered into the spool by the outbox writer. */
class Attachment
{
    public $path;
    public $label = 'attachment';

    public function __toString()
    {
        return '--8<-- ' . $this->label . "\n"
             . base64_encode((string) @file_get_contents($this->path)) . "\n";
    }
}

class DraftMessage
{
    public $subject     = '(no subject)';
    public $body        = '';
    public $attachments = [];

    /**
     * Hardening (2016, after our deserialization advisory).
     *
     * A DraftMessage that arrives from the outside is not trusted with any
     * state at all: every property is scrubbed. The one exception is the
     * subject line -- support needs it to correlate the audit-log entry with
     * the ticket -- so we grab it before the scrub and put it back after.
     */
    public function __wakeup()
    {
        $label = $this->subject;

        foreach (get_object_vars($this) as $k => $v) {
            $this->$k = null;
        }

        $this->subject = $label;
        @file_put_contents(
            AUDIT_LOG,
            sprintf("[%s] scrubbed DraftMessage (subject=%s)\n", date('c'), var_export($label, true)),
            FILE_APPEND
        );
    }

    /** Flush whatever is still queued to the outbox spool on shutdown. */
    public function __destruct()
    {
        if (!is_array($this->attachments) || $this->attachments === []) {
            return;
        }
        $buffer = '';
        foreach ($this->attachments as $item) {
            $buffer .= (string) $item;
        }
        @file_put_contents(SPOOL_FILE, $buffer, FILE_APPEND);
    }
}

function load_draft()
{
    if (empty($_COOKIE['draft'])) {
        return null;
    }
    $blob = base64_decode($_COOKIE['draft'], true);
    if ($blob === false) {
        return null;
    }
    // Only our own two model classes may be instantiated.
    $draft = @unserialize($blob, ['allowed_classes' => ['DraftMessage', 'Attachment']]);
    return $draft instanceof DraftMessage ? $draft : null;
}
