# Tooling

Freeing the funds on Ethereum is a multi step process that will likely need multiple attempts to be successful. Each attempt consists of 4 messages to be relayed, and can be retried as often as it needs to be.

The basic process is as follows:

## Message creation

Create 4 new messages using custom built payload. To do that, we can use `scribe`. Make sure you're running this from the home directory that contains the `data` directory where messages are stored.

> [!WARNING]  
> The message ID always needs to increase, and must start with 467096 at least!

```sh
scribe [msg-id] [payload]

# scribe 468100 0xfdca5e1f000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000d3e576b5dcde3580420a5ef78f3639ba9cd1b9670000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000b49dea7d6af04bd085ee67c528488f15af2559b54a5207693f678d4f4a355aa63da3979e804cadb2
```

This will create a new message in Concord, ready to be picked up for signing by relayers. The next step is to wait until enough signatures are available.

## Concord queries

Concord offers two endpoints to query the current state of signatures on messages, namely:

`curl https://concord.palomachain.com/messages` to retrieve a list of all currently governed messages.

This will get quite long over time, and often it's easier to simply look at an individual message. You can do that using `curl https://concord.palomachain.com/message/[message-id]`.

## Relay

Once enough signatures have been collected on a message to attempt a relay, we can execute it using the `relay` binary. It also needs to be run from the home directory which contains the `data` directory, and much like `whisper`, it will need access to a pigeon configuration.

> [!WARNING]  
> The messages are hard coded with the VolumeFi relayer address, therefore the configuration and keyring will need to be present on the concord host for this to work.

```sh
relay [msg-id] [path-to-pigeon-config] [eth-rpc-url]

# relay 468100 ~/.pigeon/config.yaml https://ethrpc.com
```

The relayer will return a transaction hash which can be looked up on an explorer if run successful, or hopefully a meaningful error message to trace.

Once all four messages will have been relayed successfully, this operation can be considered completed.
