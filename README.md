> [!IMPORTANT]
> this project is still **VERY** Work-in-progress. **13.20** is fully
> supported. **13.60** now has its offset table (`off_1360.c`, from
> Byepervisor-Reborn's `13_60.h`) and the escape/hook path wired up, so the
> hypervisor escape runs on 13.60 -- but the post-resume takeover offsets are
> still missing, so Linux does not boot yet. see [13.60 port](#1360-port).

# pLinux5-NG

boot linux on PS5 consoles running high firmware (8.xx through 13.60) 

this project is a port/rework of the existing [ps5-linux-loader](https://github.com/ps5-linux/ps5-linux-loader) 
(which currently works on 3.00 though 7.61) to the new [byepervisor-reborn](https://github.com/PS5Dev/Byepervisor-Reborn) hypervisor escape 

- the linux boot path itself (bzImage/initrd relocation, `boot_params`/e820 setup,
  hardware bring up, SVM/IOMMU teardown, the jump to `startup_64`) is brought over
  from the existing ps5-linux-loader
- the *escape* -- how we get code running in hypervisor root mode on all cores on high firmware --
  is what has changed in this project. on 3.00 through 7.61 its flatz' ACPI-wakeup ROP
  chain; on high firmware it is a khook on the S3-resume `HV_MP_STARTUP_CALL` path. as implemented
  in Byepervisor-Reborn.

## 13.60 port

13.60 reuses the 13.20 escape and boot path verbatim; only the offset values
change. What is in place today:

- `source/offsets/off_1360.c` -- kernel/HV symbols and gadgets, taken from
  Byepervisor-Reborn's [`include/offsets/13_60.h`](https://github.com/EchoStretch/Byepervisor-Reborn/blob/main/include/offsets/13_60.h)
- `include/hv/defeat/hv_defeat_1360.h` + `source/hv/defeat/hv_defeat_1360.c`
- routing in `source/main.c` / `source/core/utils.c` (`case 0x1360`)

With these, the Byepervisor khook escape (make kernel `.text` RW, clear XOTEXT,
install the S3-resume `HV_MP_STARTUP_CALL` hook, redirect to `break_hv`) runs on
13.60 and the console resumes with NPT disabled.

**Still missing for a Linux boot** (post-resume takeover, phase B): four
firmware-specific addresses that are *not* in Byepervisor's `13_60.h` and have
to be pulled from a real 13.60 console dump:

| value | 13.20 reference | where it lives |
|---|---|---|
| HV VMMCALL handler PA (dmap) | `0x62847375` | `hv_defeat_1360.c` |
| `KERNEL_CFI_CHECK` | `0x44E5D0` | `off_1360.c` |
| `FUN_SMP_RENDEZVOUS` | `0xAF94E0` | `off_1360.c` |
| hypercall-4 wrapper | `0xC09E40` | `hv_defeat_1360.c` |

the shared takeover blob (`source/shellcode/hv_takeover/`) is also 13.20-hard-
coded and needs the same treatment. until then `PL5_1360_TAKEOVER=0` (default)
keeps phase B compiled out, so the 13.60 build is safe to run and stops after
confirming the escape. run `tools/pl5-offsets.elf` on a 13.60 console to produce
the dump that fills these in.

## usage

### **CRITICAL** 
ps5 configuration:
- enable rest mode features:
    - `settings` -> `system` -> `power saving` -> `features available in rest mode`, set `Supply Power to USB Ports` to `Always`
- disable HDMI device link:
    - `settings` -> `system` -> `HDMI`, set `Enable HDMI Device Link` to be `off` 
  

# installation

follow the [ps5-linux-loader installation guide](https://github.com/ps5-linux/ps5-linux-loader#installation) until you get to
step 4, then come back here.

### running the jailbreak

- set your playstations DNS to `45.56.67.85`:
  - `settings` -> `network` -> `settings` -> `set up internet connection` then click the `options` button on
  your controller, select `advanced settings`, from there set `primary DNS` to `45.56.67.85` then select `ok`, if
  done correctly, you will get a popup saying `internet connection failed`, thats good, continue.

- navigate to the users guide:
  - `settings` -> `Guide & Tips, Health and Safety, and Other Information` -> `User's Guide`.
  - when a popup appears saying: `the security of the page can't be confirmed...`, click `yes`
    
- you should end up on a page with big letters saying `RELAPSE`, click the `Jailbreak` button & wait for it to finish
  it finishing will be marked by elfldr starting.

now download the `pLinux5-NG.elf` file from releases, or see [building](#building) to build from source, then move to [sending](#sending)


# building

## locally
requires the [PS5 payload SDK](https://github.com/ps5-payload-dev/sdk), the [pLabs5-SDK](https://github.com/pLabs5/pLabs5-SDK) and a C compiler:

```bash
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
LLVM_CONFIG=/path/to/pLabs5-SDK/tools/nixos/llvm-config
make -j
```

the output is `bin/pLinux5-NG.elf`.

The shellcode blobs are compiled freestanding with the host `gcc`
(`-ffreestanding -nostdlib`) and embedded as C headers; `scripts/bin2c.py`
replaces `xxd -i`, which is not present in every environment.

## docker
run
```shell
docker buildx bake
```
the output will be at `bin/pLinux5-NG.elf`.

### sending

on linux/unix, use:
```bash
# (from the area with the repo + pLinux5-NG.elf) 
cd scripts/
chmod +x send.sh
./send.sh PS5_IP=<Playstation 5s IP> PS5_PORT=9021
```
on windows, if using powershell, use:
```powershell
.\scripts\send.ps1 -PS5IP <Playstation 5s IP> -Port 9021
```
otherwise, if using CMD/Command Prompt, use:
```cmd
powershell -ExecutionPolicy Bypass -File .\scripts\send.ps1 -PS5IP <Playstation 5s IP> -Port 9021
```

## License

This project is licensed under the **AGPL-3.0** licence.
The boot path and shellcode are derived from **ps5-linux-loader**, which is
**GPL-3.0**; those files retain their original authorship and are used here in
accordance with the GPL/AGPL compatibility provisions. The high-firmware escape
is adapted from **Byepervisor-Reborn**.

## legal
I, niko86c/pLabs5, as well as its contributers, are not affiliated with, associated with, sponsored by, endorsed by or otherwise established with Sony Interactive Entertainment, Playstation, or any of their other companies or works unless explictly stated otherwise.
***Just because a explict mention above isn't present does **NOT** mean otherwise.***

All software is provided "as is", without warranty of **ANY** kind, express
or implied. Use all software at your own risk.

You are solely responsible for complying with terms of service of all programs, as well as any applicable law. 
