FIX ASCII ERROR: export PYTHONIOENCODING=UTF-8

``
Capture
``
- uses /proc/net/dev to detect incoming ddos attacks.

- currently uses UFW (fucking stinky. i know.)

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

https://user-images.githubusercontent.com/58793605/132091994-cb92580e-ac59-4f41-9d27-0bad34f35c4e.mp4

^ outdated as fuck ill fix when i can be asked

