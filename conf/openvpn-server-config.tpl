management {{ .Management }}

port {{ .Port }}
proto {{ .Proto }}

dev tap

ca {{ .Ca }}
cert {{ .Cert }}
key {{ .Key }}

cipher {{ .Cipher }}
keysize {{ .Keysize }}
auth {{ .Auth }}
dh {{ .Dh }}

server-bridge 10.8.0.4 255.255.255.0 10.8.0.50 10.8.0.100
ifconfig-pool-persist {{ .IfconfigPoolPersist }}
push "route 10.8.0.0 255.255.255.0"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
client-to-client
keepalive {{ .Keepalive }}

comp-lzo
max-clients {{ .MaxClients }}

persist-key
persist-tun

log         openvpn.log
verb 3

mute 10
