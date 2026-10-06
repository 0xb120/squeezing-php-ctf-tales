<?php
/**
 * Fleet Console 0.3 - the two drivers this build ships with.
 * A driver is instantiated once per licensed slot and asked to probe it.
 */

abstract class Driver
{
    /** @return bool true when the slot is usable */
    abstract public function probe($slot);
}

class NullDriver extends Driver
{
    public function probe($slot)
    {
        return false;
    }
}

class LocalDriver extends Driver
{
    public function probe($slot)
    {
        return is_dir('/tmp/fleet/' . $slot);
    }
}
