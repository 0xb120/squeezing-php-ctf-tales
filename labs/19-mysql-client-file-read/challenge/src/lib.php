<?php
/**
 * Nimbus Panel - shared helpers.
 */

/**
 * A small buffered logger.  Call write() as often as you like; whatever is
 * still buffered gets flushed to disk when the object is collected, so a
 * fatal error halfway through a request does not lose the trail.
 */
class DebugLogger
{
    public $logfile;
    public $buffer = '';

    public function __construct($logfile = '/tmp/nimbus-panel.log')
    {
        $this->logfile = $logfile;
    }

    public function write($line)
    {
        $this->buffer .= '[' . date('c') . '] ' . $line . "\n";
    }

    public function __destruct()
    {
        if ($this->buffer !== '') {
            file_put_contents($this->logfile, $this->buffer, FILE_APPEND);
        }
    }
}

/** Where operator-supplied avatars land. */
function uploads_dir()
{
    return __DIR__ . '/uploads';
}
