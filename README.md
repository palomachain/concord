# Concord
---

> [!WARNING]  
> Quickly hacked together in an attempt to manually send a valset signed message to target chains.

Concord represents our effort to recover messages stuck on older networks that have since become obsolete.
In order to clean up running bots on remote chains, the Paloma validators will need to manually sign messages
intended to be relayed to mothballed versions of compass.

The main components to reach this goal are:

- `concord`, a centralised server binary which contains the message information and collects signatures from participants
- `whisper`, a daemon for local execution on validator machine, that connects to `concord`, listens for any outstanding messages and sends a signature for those using the local `Pigeon` configuration.

## How to use


> [!NOTE]  
> Whisper expects an identical setup to Pigeon, which means you potentially may need to export any environment variables used within your configuration and keyring setup.

We advise relayers to install Whisper on the same machine they use for Pigeon.

The setup should be fairly straight-forward for validators. Simply download the latest release of `whisper` and execute. You will need your Pigeon configuration that was used with the `messenger` network of Paloma, including your Ethereum mainnet signing keys.

### Install the binary

```sh
wget -O - https://github.com/palomachain/concord/releases/download/v1.0.0/whisper_Linux_x86_64.tar.gz  | \
  sudo tar -C /usr/local/bin -xvzf - whisper
sudo chmod +x /usr/local/bin/whisper

```

### Running the binary
Running the binary takes two additional arguments:

1. The path to your pigeon configuration file: this is used in order to apply your consensus key to the message. Compass expects at least 2/3 of the latest deployed valset to participate in this consensus before accepting an incoming message.
2. The URL of `concord` that you wish to connect to.

```sh
./whisper ~/.pigeon/config.yaml https://concord.palomachain.com
```

### Running as a service
You can also run whisper using a simple service configuration:
```sh
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

```
