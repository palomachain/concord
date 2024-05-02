# Paloma Recovery Tool for abandoned Compass-EVM funds on `messenger` blockchain.
---

## Instructions for Paloma Validators to run Whisper to Recover ETH from `messenger` blockchain's Compass-EVM.

> [!NOTE]  
No new server needed. Validators **MUST** install Whisper on the same machine used for Paloma's Pigeon, today.

### Download the latest release of `whisper` and execute. 
You will need your Pigeon configuration to be the same as it was on the `messenger` network of Paloma, including your Ethereum mainnet signing keys.

### Install the binary

```sh
wget -O - https://github.com/palomachain/concord/releases/download/v1.0.0/whisper_Linux_x86_64.tar.gz  | \
  sudo tar -C /usr/local/bin -xvzf - whisper
sudo chmod +x /usr/local/bin/whisper

```

### Run the binary as a service
Set up whisper to run as a service configuration. Whisper will need to keep running until all validators have installed the binary and the messages were relayed. We will alert validators when whisper can be shut off and removed again.
```sh
cat <<EOT >/etc/systemd/system/whisper.service
[Unit]
Description=Whisper daemon
After=network-online.target
ConditionPathExists=/usr/local/bin/whisper

[Service]
Type=simple
Restart=always
RestartSec=5
User=root
WorkingDirectory=~
EnvironmentFile=/root/.pigeon/env.sh
ExecStart=/usr/local/bin/whisper ~/.pigeon/config.yaml https://concord.palomachain.com
ExecReload=

[Install]
WantedBy=multi-user.target
EOT
```
