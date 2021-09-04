``
Capture
``
- uses /proc/net/dev to detect incoming ddos attacks.

``
settings.json
``
- interface, you can find this by typing "ifconfig".
- directory, the directory where you want to save the attack logs.
- threshold, how many current PPS you want to trigger detection. (if you get false positives set this higher)
- checks, amount of time to check /proc/net/dev to trigger pps detection.
- sleep_time, amount of time to wait after capturing an attack.
- dump_size, amount of packets you would like to capture when attack is detected.
