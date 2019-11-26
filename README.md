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
| sr | Sample rate |

### Second stage (stream session)

| Key | Description |
|:---:|-------------|
| ct | Compression type |
| shk | Shared encryption key |
| spf | Frames per packet |
| sr | Sample rate |

