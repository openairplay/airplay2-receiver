# Experimental

Very quick python implementation of AP2 pairing and play using **minimal
multi-room** features.

To run _rareport-proto_ please use Python 3 and do the following:

* open the _event_ server;

```
nc -lk 0.0.0.0 <EPORT>
```

* open the _data_ server;

```
nc -ulk 0.0.0.0 <DPORT>
```

* open the _control_ server;

```
nc -ulk 0.0.0.0 <CPORT>
```

* start _rareport-proto_;

```
virtualenv proto
source proto/bin/activate
pip install -r requirements.txt
python rareport-proto.py -m rareport -e <EPORT> -d <DPORT> -c <CPORT>
```

* the AirPlay 2 receiver is announced as **rareport**.

Tested on Python 3.7.5 / macOS 10.15.1 with iPhone X 13.2.3

#wip explain messages exchanged

# AirPlay internal acronyms

## From mDNS TXT record

| FromTXTRecord | ToDict | Type | Explanation |
|:-------------:|--------|------|-------------|
| cn | compressionTypes | BitList | Compression types |
| da | rfc2617DigestAuthKey | Boolean | RFC2617 digest auth key |
| et | encryptionTypes | BitList | Encryption types |
| ft | features | Int64 | Features |
| fv | firmwareVersion | String | Firmware version |
| sf | systemFlags | Int64 | System flags |
| md | metadataTypes | BitList | Metadata types |
| am | deviceModel | String | Device model |
| pw | password | Boolean | Password |
| pk | publicKey | String | Public key |
| tp | transportTypes | String | Transport types |
| vn | airTunesProtocolVersion | String | AirTunes protocol version |
| vs | airPlayVersion | String | AirPlay version |
| ov | OSVersion | String | OS version |
| vv | vodkaVersion | Int64 | Vodka version |
| acl | accessControlLevel | Int64 | Access control level |
| btaddr | bluetoothAddress | String | Bluetooth address |
| deviceid | deviceID | String | Device ID |
| features | features | Int64 | Features |
| rsf | requiredSenderFeatures | Int64 | Required sender features |
| flags | systemFlags | Int64 | System flags |
| gcgl | groupContainsDiscoverableLeader | Boolean | Group contains discoverable leader |
| gid | groupUUID | String | Group UUID |
| gpn | groupPublicName | String | Group public name |
| igl | isGroupLeader | Boolean | Is group leader |
| hgid | homeGroupUUID | String | Home group UUID |
| hmid | householdID | String | Household ID |
| pgcgl | parentGroupContainsDiscoverableLeader | Boolean | Parent group contains discoverable leader |
| pgid | parentGroupUUID | String | Parent group UUID |
| tsid | tightSyncUUID | String | Tight sync UUID |
| hkid | homeKitHomeUUID | String | HomeKit home UUID |
| model | deviceModel | String | Device model |
| manufacturer | manufacturer | String | Manufacturer |
| serialNumber | serialNumber | String | Serial number |
| protovers | protocolVersion | String | Protocol version |
| pi | publicCUAirPlayPairingIdentity | String | Public CU AirPlay pairing identity |
| psi | publicCUSystemPairingIdentity | String | Public CU System Pairing Identity |
| pk | publicKey | String | Public key |
| srcvers | airPlayVersion | String | AirPlay version |
| osvers | OSVersion | String | OS version |

## From RSTP SETUP requests

### First stage

| Key | Description |
|:---:|-------------|
| et | Encryption type |
| ekey | Encryption key |
| eiv | Encryption initialization vector |

### Second stage (stream session)

| Key | Description |
|:---:|-------------|
| ct | Compression type |
| shk | Shared encryption key |
| spf | Frames per packet |
| sr | Sample rate |


# Audio Stream Formats

| Bit | Value | Type |
|:---:|:-----:|------|
| 2 | 0x4 | PCM/8000/16/1 |
| 3 | 0x8 | PCM/8000/16/2 |
| 4 | 0x10 | PCM/16000/16/1 |
| 5 | 0x20 | PCM/16000/16/2 |
| 6 | 0x40 | PCM/24000/16/1 |
| 7 | 0x80 | PCM/24000/16/2 |
| 8 | 0x100 | PCM/32000/16/1 |
| 9 | 0x200 | PCM/32000/16/2 |
| 10 | 0x400 | PCM/44100/16/1 |
| 11 | 0x800 | PCM/44100/16/2 |
| 12 | 0x1000 | PCM/44100/24/1 |
| 13 | 0x2000 | PCM/44100/24/2 |
| 14 | 0x4000 | PCM/48000/16/1 |
| 15 | 0x8000 | PCM/48000/16/2 |
| 16 | 0x10000 | PCM/48000/24/1 |
| 17 | 0x20000 | PCM/48000/24/2 |
| 18 | 0x40000 | ALAC/44100/16/2 |
| 19 | 0x80000 | ALAC/44100/24/2 |
| 20 | 0x100000 | ALAC/48000/16/2 |
| 21 | 0x200000 | ALAC/48000/24/2 |
| 22 | 0x400000 | AAC-LC/44100/2 |
| 23 | 0x800000 | AAC-LC/48000/2 |
| 24 | 0x1000000 | AAC-ELD/44100/2 |
| 25 | 0x2000000 | AAC-ELD/48000/2 |
| 26 | 0x4000000 | AAC-ELD/16000/1 |
| 27 | 0x8000000 | AAC-ELD/24000/1 |
| 28 | 0x10000000 | OPUS/16000/1 |
| 29 | 0x20000000 | OPUS/24000/1 |
| 30 | 0x40000000 | OPUS/48000/1 |
| 31 | 0x80000000 | AAC-ELD/44100/1 |
| 32 | 0x100000000 | AAC-ELD/48000/1 |
