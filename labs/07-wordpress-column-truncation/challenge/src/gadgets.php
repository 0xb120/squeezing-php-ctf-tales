<?php
/**
 * inkpress -- two perfectly ordinary classes from the media/notification code.
 */

/** Inlines a small asset into a rendered page. */
class MediaItem
{
    public $path;
    public $alt = 'image';

    public function __toString()
    {
        return '[' . $this->alt . '] ' . base64_encode((string) @file_get_contents($this->path));
    }
}

/** Buffers dashboard notices and flushes them to the activity log on shutdown. */
class ActivityLog
{
    public $entries = [];
    public $sink    = null;

    public function __destruct()
    {
        if (!is_array($this->entries) || $this->entries === []) {
            return;
        }
        $buffer = '';
        foreach ($this->entries as $entry) {
            $buffer .= (string) $entry . "\n";
        }
        @file_put_contents($this->sink ?: ACTIVITY_LOG, $buffer, FILE_APPEND);
    }
}
