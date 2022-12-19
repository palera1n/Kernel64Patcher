# Kernel64Patcher
A 64 Bit kernel patcher based on xerub's patchfinder64, forked for palera1n

## Compiling
```
make
```

## Usage:
```
./Kernel64Patcher <kernel_in> <kernel_out> <args>
        -a              Patch AMFI
        -f              Patch AppleFirmwareUpdate img4 signature check
        -s              Patch SPUFirmwareValidation (iOS 15 Only)
        -r              Patch RootVPNotAuthenticatedAfterMounting (iOS 15 Only)
        -o              Patch could_not_authenticate_personalized_root_hash (iOS 15 Only)
        -e              Patch root volume seal is broken (iOS 15 Only)
        -u              Patch update_rootfs_rw (iOS 15 Only)
        -p              Patch AMFIInitializeLocalSigningPublicKey (iOS 15 Only)
        -h              Patch is_root_hash_authentication_required_ios (iOS 16 only)
        -l              Patch launchd path
        -t              Patch tfp0
        -d              Patch developer mode
```

## Credits/Thanks
* xerub for patchfinder64
* iH8sn0w for code
