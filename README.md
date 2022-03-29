# Sheller

Sheller tunnels any shell sessopm (primarily SSH) over HTTP
websockets.

Based on https://github.com/google/huproxy

Sheller is a component of the Mist Cloud Management Platform.

## Setup

### nginx

#### Create user

```
sudo htpasswd -c /etc/nginx/users.proxy thomas
```

#### Add config to nginx

```
map $http_upgrade $connection_upgrade {
    default upgrade;
         '' close;
}
location /proxy {
    auth_basic "Proxy";
    auth_basic_user_file /etc/nginx/users.proxy;
    proxy_pass http://127.0.0.1:8086;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    # proxy_set_header Connection "upgrade";
    proxy_set_header Connection $connection_upgrade;
}
```

Start proxy:

```
./sheller
```

## Running

These commands assume that HTTPS is used. If not, then change "wss://"
to "ws://".

```
echo thomas:secretpassword > ~/.sheller.pw
chmod 600 ~/.sheller.pw
cat >> ~/.ssh/config << EOF
Host shell.example.com
    ProxyCommand /path/to/shellerclient -auth=@$HOME/.sheller.pw wss://proxy.example.com/proxy/%h/%p
EOF

ssh shell.example.com
```

Or manually with these commands:

```
ssh -o 'ProxyCommand=./shellerclient -auth=thomas:secretpassword wss://proxy.example.com/proxy/%h/%p' shell.example.com
ssh -o 'ProxyCommand=./shellerclient -auth=@<(echo thomas:secretpassword) wss://proxy.example.com/proxy/%h/%p' shell.example.com
ssh -o 'ProxyCommand=./shellerclient -auth=@$HOME/.sheller.pw wss://proxy.example.com/proxy/%h/%p' shell.example.com
```
