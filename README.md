# COMP8006LoginMonitorBlock

The ipblocker program works on Linux by reading the secure log and looking for new entries that contain key words such as "failed password" or "failed login"


After a number of attempts defined in the ipblocker.config, it will block the IP from interacting with the server for a specified amount of time.


Timeout: The maximum amount of time allowed before the max attempts resets to 0

Locktime: Blocks the IP for a specified amount of seconds when MaxAttempts has been reached, Locktime=0 is forever block

MaxAttempts: Maximum number of attempts before an IP is blocked
