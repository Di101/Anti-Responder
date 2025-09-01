## RU
Модуль написан в далёком 2022 году. Залит как есть, спустя долгое время, поэтому может не заработать «из коробки». <br>
Код был написан с целью детектирования запуска Responder в локальной сети. <br>
По ходу развития проекта добавлен функционал детектирования DNS-spoofing и ARP-spoofing, который позволяет выявлять обход port-security путём подмены MAC-адреса атакующего на MAC-адрес вендора принтеров. <br>
В модуле AntiResponder реализован функционал ханипота: злоумышленник получит ханипотные учётные данные — по SMB в виде NTLM/NTLMv2 хешей и по HTTP в открытом виде. <br>
В случае алерта создаются события в логе Application с кодами 3001–3003. <br>
<br>
Модули: <br>
AntiResponder; <br>
Anti-DNS-Spoofing; <br>
Anti-ARP-Spoofing <br>

---

## EN
The module was written back in 2022. It’s uploaded as-is after a long gap, so it may not work out of the box. <br>
The code was originally created to detect the launch of Responder on a local network. <br>
As the project evolved, detection for DNS spoofing and ARP spoofing was added, enabling detection of port-security bypass by replacing the attacker’s MAC address with a printer vendor’s MAC address. <br>
The AntiResponder module also implements a honeypot: an attacker will receive decoy credentials — over SMB as NTLM/NTLMv2 hashes, and over HTTP in clear text. <br>
On alert, events 3001–3003 are written to the Application log. <br>
<br>
Modules: <br>
AntiResponder; <br>
Anti-DNS-Spoofing; <br>
Anti-ARP-Spoofing <br>
