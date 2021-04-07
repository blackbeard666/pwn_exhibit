# CTF Writeups

## [https://gist.github.com/blackbeard666/](https://gist.github.com/blackbeard666/)
#### Solve scripts for challs that I don't have the time to create writeups for (or that the basic idea has been covered in other writeups here, only with a few additions). Might still create writeups for them tho.

## 2021
* * *


### Tryhackme

|-------------------------------------------------------------------|---------------------------------------|
| [Inferno](/content/2021_CTF/tryhackme/inferno/inferno_writeup.md) | `http basic auth`, `cve`              |
| [Watcher](/content/2021_CTF/tryhackme/watcher/watcher_writeup.md) | `lfi`, `cronjobs`, `multiple privesc` |

Securinets Quals CTF

|                                                                       |                                                                            |
|-----------------------------------------------------------------------|----------------------------------------------------------------------------|
| [killshot](/content/2021_CTF/securinets_qualsCTF/killshot_writeup.md) | `tcache_perthread_struct`, `printf www`, `heap rop`, `seccomp`, `analysis` |
| deathnote                                                             | `tcache poison`, `negative index write`                                    |

NahamconCTF

|                                                           |                                                  |
|-----------------------------------------------------------|--------------------------------------------------|
| [meddle](/content/2021_CTF/nahamconCTF/meddle_writeup.md) | `tcache poison`, `libc 2.27`, `misaligned input` |

BsidesSF CTF

|                                                                           |                              |
|---------------------------------------------------------------------------|------------------------------|
| [runme 1,2,3](/content/2021_CTF/bsidesSFCTF/pwn_runme_writeup.md)         | `self-modifying shellcode`   |
| [reverseme 1,2](/content/2021_CTF/bsidesSFCTF/pwn_revme_writeup.md)       | `encoded shellcode`          |
| [Charge Tracker](/content/2021_CTF/bsidesSFCTF/android_charge_writeup.md) | `android rev`, `adb dumpsys` |

zer0pts CTF

|                                                                                    |                |
|------------------------------------------------------------------------------------|----------------|
| [Not beginner's stack](/content/2021_CTF/zeroptsCTF/not_beginner_stack_writeup.md) | `shadow stack` |

DarkCon CTF

|                                                             |                                                           |
|-------------------------------------------------------------|-----------------------------------------------------------|
| [Intro](/content/2021_CTF/darkconCTF/intro.md)              | `intro`                                                   |
| [Easy-ROP](/content/2021_CTF/darkconCTF/easyrop_writeup.md) | `pwn`, `x64`, `sigrop`                                    |
| [Warmup](/content/2021_CTF/darkconCTF/warmup_writeup.md)    | `pwn`, `x64`, `libc-2.27`, `double free`, `tcache poison` |
| [ezpz](/content/2021_CTF/darkconCTF/ezpz_writeup.md)        | `android rev`, `adb logcat`                               |
| [Take it Easy](/content/2021_CTF/darkconCTF/easy_cry.md)    | `crypto`, `low exponent attack`, `e = 3`                  |

TrollCat CTF

|                                                           |                 |
|-----------------------------------------------------------|-----------------|
| [msgbox](/content/2021_CTF/trollcatCTF/msgbox_writeup.md) | `tcache poison` |
    
0x41414141 CTF

|                                                                       |                                        |
|-----------------------------------------------------------------------|----------------------------------------|
| [moving signals](/content/2021_CTF/offshiftCTF/signals_writeup.md)    | `sigrop`                               |
| [external](/content/2021_CTF/offshiftCTF/external_writeup.md)         | `fixing GOT`, `rop`                    |
| [echo](/content/2021_CTF/offshiftCTF/echo_writeup.md)                 | `sigrop`, `not fmtstr`                 |
| [return of the rops](/content/2021_CTF/offshiftCTF/retrop_writeup.md) | `unintended: rop`, `intended: ret2csu` |
| [babyheap](/content/2021_CTF/offshiftCTF/babyheap_writeup.md)         | `double free`, `tcache`                |
     
## 2020
* * *

- Grimmcon CTF
    - [sentinel](/content/2020_CTF/grimmconCTF/sentinel_writeup.md)
    - [axiom](/content/2020_CTF/grimmconCTF/axiom_writeup.md)

- Vulncon CTF
    - [warmup](/content/2020_CTF/vulnconCTF/pwn_warmup_writeup.md)
    - [name](/content/2020_CTF/vulnconCTF/pwn_name_writeup.md)
    - [looping](/content/2020_CTF/vulnconCTF/pwn_looping_writeup.md)
    - [where to go?](/content/2020_CTF/vulnconCTF/pwn_where_writeup.md)
    - [old time](/content/2020_CTF/vulnconCTF/pwn_oldtime_writeup.md)

- XMAS CTF
    - [Naughty?](/content/2020_CTF/xmasCTF/pwn_naughty/pwn_naughty_writeup.md)
    - [Ready for Xmas?](/content/2020_CTF/xmasCTF/pwn_readyxmas/pwn_ready_writeup.md)
    - [lil wishes db](/content/2020_CTF/xmasCTF/pwn_lilwishes/pwn_lilwishes_writeup.md)
    - [rev, web, misc](/content/2020_CTF/xmasCTF/rev_web_misc.md)

- boot2root CTF
    - [prologue](/content/2020_CTF/boot2rootCTF/prologue.md)
    - [canned](/content/2020_CTF/boot2rootCTF/canned_writeup.md)

- DefCamp CTF
    - [modern-login](/content/2020_CTF/DefCampCTF/modernlogin_writeup.md)

- InterIUT CTF
    - [reverse me 1](/content/2020_CTF/InterIUTCTF/android_rev1_writeup.md)
    - [reverse me 2](/content/2020_CTF/InterIUTCTF/android_rev2_writeup.md)
    - [Qui Passe](/content/2020_CTF/InterIUTCTF/android_quipasse_writeup.md)
    - [SMALI, un beau pays](/content/2020_CTF/InterIUTCTF/android_smali_writeup.md)
    - [CyberMalware](/content/2020_CTF/InterIUTCTF/android_cybermalware_writeup.md)
    - [Jankenpon](/content/2020_CTF/InterIUTCTF/android_jankenpon_writeup.md)

- Square CTF
    - [jimi-jam](/content/2020_CTF/SquareCTF/pwn_jimijam.md)

- Sunshine CTF
    - [speedrun 08](/content/2020_CTF/SunshineCTF/speedrun8_writeup.md)
    - [speedrun 14](/content/2020_CTF/SunshineCTF/speedrun12_writeup.md)

- Newark Academy CTF
    - [patches](/content/2020_CTF/NACTF/rev_patches.md)
    - [greeter](/content/2020_CTF/NACTF/pwn_greeter.md)
    - [dROPit](/content/2020_CTF/NACTF/pwn_dropit.md)
    - [format](/content/2020_CTF/NACTF/pwn_format.md)
    - [covid tracker tracker tracker](/content/2020_CTF/NACTF/pwn_cttt/cttt_writeup.md)

- CyberYoddha CTF
    - [pwn](/content/2020_CTF/CyberYoddhaCTF/pwn/pwn_writeups.md)

- Razi CTF
    - [chasing a lock](/content/2020_CTF/RaziCTF/android_lock/lock_writeup.md)
    - [strong padlock](/content/2020_CTF/RaziCTF/android_strongpadlock/strongpadlock_writeup.md)

- HackLu CTF
    - [flagdroid](/content/2020_CTF/HackLuCTF/rev_flagdroid/flagdroid_writeup.md)

- DamCTF
    - [allokay](/content/2020_CTF/DamCTF/pwn_allokay/pwn_allokay_writeup.md)
    - [finger-warmup](/content/2020_CTF/DamCTF/web_fingerwarmup/web_writeup.md)
    - schlage
    - [malware phase 1](/content/2020_CTF/DamCTF/malware1/writeup_malware1.md)
    
- b01lers bootcamp CTF
    - [a brief intro](/content/2020_CTF/b01lers_bootcamp/brief_intro.md)
    - [metacortex](/content/2020_CTF/b01lers_bootcamp/pwn_metacortex/metacortex_writeup.md) 
    - [there is no spoon](/content/2020_CTF/b01lers_bootcamp/pwn_nospoon/nospoon_writeup.md)
    - [oracle](/content/2020_CTF/b01lers_bootcamp/pwn_oracle/oracle_writeup.md)
    - [whiterabbit](/content/2020_CTF/b01lers_bootcamp/pwn_whiterabbit/whiterabbit_writeup.md)
    - [free your mind](/content/2020_CTF/b01lers_bootcamp/pwn_freemind/freeurmind_writeup.md)
    - [see for yourself](/content/2020_CTF/b01lers_bootcamp/pwn_seeforyourself/seeforyourself_writeup.md)

- Bsides Delhi CTF
    - [lazy](/content/2020_CTF/BsidesDelhi/lazy_writeup.md)
    
- Bsides Boston CTF
    - [seashells, mobility, y2k](/content/2020_CTF/BsidesBoston/writeups.md)

- EKOPARTY CTF
    - [Entry [1-5]](/content/2020_CTF/EKOPARTY/writeup_entry.md)
    - [C&C [1-3,5]](/content/2020_CTF/EKOPARTY/writeup_cc.md)
    - [Trivia [1,2,5]](/content/2020_CTF/EKOPARTY/writeup_trivia.md)

- Dark CTF
    - [so much](/content/2020_CTF/DarkCTF/writeup_so_much.md)
    - [roprop](/content/2020_CTF/DarkCTF/writeup_roprop.md)
    - [newPaX](/content/2020_CTF/DarkCTF/writeup_newpax.md)
    - [rrop](/content/2020_CTF/DarkCTF/writeup_rrop.md)

- DownUnder CTF
    - [shell this!](/content/2020_CTF/DownUnder/pwn_shellthis/writeup_pwn_shellthis.md)
    - [return to what](/content/2020_CTF/DownUnder/pwn_return_to_what/writeup_pwn_returntowhat.md)
    - [return to what's revenge](/content/2020_CTF/DownUnder/pwn_returntowhats_revenge/writeup_pwn_returntorevenge.md)

- CSAW Qualifiers
    - [roppity](/content/2020_CTF/CSAW_quals/pwn_roppity/writeup_pwn_roppity.md)
    - [slithery](/content/2020_CTF/CSAW_quals/pwn_slithery/writeup_pwn_slithery.md)

- Google CTF
    - [Android](/content/2020_CTF/GoogleCTF/re_android/android_writeup.md)

- Fword CTF
    - [Welcome Pwner](/content/2020_CTF/FwordCTF/writeup_pwn_welcome.md)
    - [One Piece](/content/2020_CTF/FwordCTF/writeup_pwn_onepiece.md)
    
- Arab Sec Cyber Wargames Qualifiers
    - [check](/content/2020_CTF/ArabSecCWG/writeup_check.md)
    - DOOM

## 2019
* * *    
- AngstromCTF
    - [Aquarium](/content/2019_CTF/angstromCTF/writeup_aquarium.md)
    - [Chain of Rope](/content/2019_CTF/angstromCTF/writeup_chain_of_rope.md)
    - [Purchases](/content/2019_CTF/angstromCTF/writeup_purchases.md)
    - [I Like It](/content/2019_CTF/angstromCTF/writeup_i_like_it.md)
    - [One Bite](/content/2019_CTF/angstromCTF/writeup_one_bite.md)

- TJCTF
    - [Silly Sledshop](/content/2019_CTF/TJCTF/writeup_silly_sledshop.md)
    
- EncryptCTF
    - [pwn0](/content/2019_CTF/encryptCTF/writeup_pwn0.md)
    - [pwn1](/content/2019_CTF/encryptCTF/writeup_pwn1.md)
    - [pwn2](/content/2019_CTF/encryptCTF/writeup_pwn2.md)
    - [pwn3](/content/2019_CTF/encryptCTF/writeup_pwn3.md)
    - [pwn4](/content/2019_CTF/encryptCTF/writeup_pwn4.md)
    
- SunshineCTF
    - [Return To Mania](/content/2019_CTF/sunshineCTF/writeup_return_to_mania.md)
     
- TamuCTF
    - [pwn1](/content/2019_CTF/tamuCTF/writeup_pwn1.md)
    - [pwn2](/content/2019_CTF/tamuCTF/writeup_pwn2.md)
    - [pwn3](/content/2019_CTF/tamuCTF/writeup_pwn3.md)
    - [pwn4](/content/2019_CTF/tamuCTF/writeup_pwn4.md)

- FireshellCTF
    - [Casino](/content/2019_CTF/fireshellCTF/writeup_casino.md)
    - [Leakless](/content/2019_CTF/fireshellCTF/writeup_leakless.md)
