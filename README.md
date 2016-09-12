tracewrite - a simple DTrace script for writev & friends
--

Usage:

    sudo dtrace -s tracewrite.d -p <process ID>
    
(If you've only got one instance of the BEAM running, you might do `-p $(pgrep beam)` for convenience.)

DTrace doesn't support looping constructs so there are separate actions for the
first ~15 entries of the writev vector.
