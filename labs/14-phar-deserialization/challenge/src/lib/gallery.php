<?php
// Tiny "image gallery" support library.  Nothing here is reachable from the
// outside on purpose -- it is the application's own model layer.

define('CACHE_DIR', __DIR__ . '/../data');
define('UPLOAD_DIR', __DIR__ . '/../uploads');

/**
 * Rendered <figure> caption for a thumbnail.  Stored in the cache as a plain
 * string, hence the __toString().
 */
class ImageNote
{
    public $width = 0;
    public $height = 0;
    public $note = '';

    public function __construct($w = 0, $h = 0, $note = '')
    {
        $this->width = $w;
        $this->height = $h;
        $this->note = $note;
    }

    public function __toString()
    {
        return "<!-- {$this->width}x{$this->height} -->" . $this->note;
    }
}

/**
 * Write-behind cache: the entry is flushed to disk when the object dies, so a
 * request never blocks on the filesystem.
 */
class ThumbnailCache
{
    public $name;
    public $content = null;

    public function __construct($name = null, $content = null)
    {
        $this->name = $name;
        $this->content = $content;
    }

    public function put($content)
    {
        $this->content = $content;
    }

    public function __destruct()
    {
        if ($this->content !== null && $this->name !== null) {
            file_put_contents(CACHE_DIR . '/' . $this->name, (string) $this->content);
        }
    }
}
