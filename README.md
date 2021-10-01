
apt install net-tools

``
Capture
``
- uses /proc/net/dev to detect incoming ddos attacks.

- uses linux's built in IP handler

- don't use this tool if you have an iq below 10

``
weird shit
``
- when script is screened all the colors die...? idk why

``
settings.json
``
- interface, you can find this by typing "ifconfig".
- directory, the directory where you want to save the attack logs.
- threshold, how many current PPS you want to trigger detection. (if you get false positives set this higher)
- checks, amount of time to check /proc/net/dev to trigger pps detection.
- sleep_time, amount of time to wait after capturing an attack.
- dump_size, amount of packets you would like to capture when attack is detected.
- whitelist, whitelisted ips to not be blocked on mitigation

``
soon to be added
``
- Webhook alerts, only problem with this is some servers won't be able to send the webhook request when it's being hit 

``
example
``
 
 
- sent a small attack with udp method

https://gyazo.com/b59d56cf7033db235a1e3840a7193e77
