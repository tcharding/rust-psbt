# rust-bitcoin Ports

The `rust-psbt` package was originally spun out of the `bitcoin` module of `rust-bitcoin`. The rust-psbt
code was from the `0.32.x` branch though, while the `master` branch had quiet a few fixes. We can fold
these ports into the code here once we upgrade the `bitcoin` dependency beyond `0.32.x` (or start to
get some of the new crates being spun out).

| Pull Request                                                    | Merge Hash | Dependency   |
|:----------------------------------------------------------------|:-----------|:-------------|
| [#4200](https://github.com/rust-bitcoin/rust-bitcoin/pull/4200) | 6620a298   | `ArrayExt`   |
| [#4250](https://github.com/rust-bitcoin/rust-bitcoin/pull/4250) | 5f4075a0   | `hex`        |
| [#5467](https://github.com/rust-bitcoin/rust-bitcoin/pull/5467) | 490a209e   | `bitcoin`    |
| [#4788](https://github.com/rust-bitcoin/rust-bitcoin/pull/4788) | 60cce6de   | `bitcoin`    |
| [#4440](https://github.com/rust-bitcoin/rust-bitcoin/pull/4440) | 5e0b86d2   | `secp256k1`  |
| [#3164](https://github.com/rust-bitcoin/rust-bitcoin/pull/3164) | c061d936   | `bitcoin`    |
| [#3155](https://github.com/rust-bitcoin/rust-bitcoin/pull/3155) | 3119ade3   | `bitcoin`    |
| [#2878](https://github.com/rust-bitcoin/rust-bitcoin/pull/2878) | 0554c282   | `bitcoin`    |
| [#2868](https://github.com/rust-bitcoin/rust-bitcoin/pull/2868) | 4defdb08   | `bitcoin`    |
| [#2852](https://github.com/rust-bitcoin/rust-bitcoin/pull/2852) | 72ce271b   | `hashes`     |
| [#2794](https://github.com/rust-bitcoin/rust-bitcoin/pull/2794) | de7da692   | `bitcoin`    |
| [#2585](https://github.com/rust-bitcoin/rust-bitcoin/pull/2585) | 65a5dfcd   | `bitcoin`    |
| [#4616](https://github.com/rust-bitcoin/rust-bitcoin/pull/4616) | 1fee0755   | `units`      |
| [#4623](https://github.com/rust-bitcoin/rust-bitcoin/pull/4623) | d84745fd   | `bitcoin`    |
| [#3354](https://github.com/rust-bitcoin/rust-bitcoin/pull/3354) | da462d67   | `bitcoin`    |
| [#3544](https://github.com/rust-bitcoin/rust-bitcoin/pull/3544) | 4c8347a7   | `bitcoin`    |
| [#6049](https://github.com/rust-bitcoin/rust-bitcoin/pull/6049) | 0aadf9b6   | `bitcoin`    |
| [#5881](https://github.com/rust-bitcoin/rust-bitcoin/pull/5881) | d41a5b26   | `bitcoin`    |
| [#5879](https://github.com/rust-bitcoin/rust-bitcoin/pull/5879) | 253a8226   | `bitcoin`    |
| [#5797](https://github.com/rust-bitcoin/rust-bitcoin/pull/5797) | e9e6b1cb   | `bitcoin`    |
| [#5740](https://github.com/rust-bitcoin/rust-bitcoin/pull/5740) | d1e96004   | `bitcoin`    |
| [#5736](https://github.com/rust-bitcoin/rust-bitcoin/pull/5736) | c6d06a10   | `bitcoin`    |
| [#5735](https://github.com/rust-bitcoin/rust-bitcoin/pull/5735) | 83567026   | `bitcoin`    |
| [#5710](https://github.com/rust-bitcoin/rust-bitcoin/pull/5710) | 70f13c88   | `bitcoin`    |
| [#5680](https://github.com/rust-bitcoin/rust-bitcoin/pull/5680) | c54898c0   | `bitcoin`    |
| [#5657](https://github.com/rust-bitcoin/rust-bitcoin/pull/5657) | 144d27fc   | `bitcoin`    |
| [#5645](https://github.com/rust-bitcoin/rust-bitcoin/pull/5645) | 6d169a99   | `bitcoin`    |
| [#5640](https://github.com/rust-bitcoin/rust-bitcoin/pull/5640) | 29c62f61   | `bitcoin`    |
| [#5634](https://github.com/rust-bitcoin/rust-bitcoin/pull/5634) | d528d072   | `bitcoin`    |
| [#5614](https://github.com/rust-bitcoin/rust-bitcoin/pull/5614) | 98c71489   | `bitcoin`    |
| [#5593](https://github.com/rust-bitcoin/rust-bitcoin/pull/5593) | 6c0d837e   | `bitcoin`    |
| [#5573](https://github.com/rust-bitcoin/rust-bitcoin/pull/5573) | a05c7ab7   | `bitcoin`    |
| [#5374](https://github.com/rust-bitcoin/rust-bitcoin/pull/5374) | db7ea1df   | `bitcoin`    |
| [#5341](https://github.com/rust-bitcoin/rust-bitcoin/pull/5341) | 2c828ec9   | `bitcoin`    |
| [#5249](https://github.com/rust-bitcoin/rust-bitcoin/pull/5249) | 152188ee   | `bitcoin`    |
| [#4959](https://github.com/rust-bitcoin/rust-bitcoin/pull/4959) | e0a2240b   | `secp256k1`  |
| [#4907](https://github.com/rust-bitcoin/rust-bitcoin/pull/4907) | 82a87c67   | `bitcoin`    |
| [#4881](https://github.com/rust-bitcoin/rust-bitcoin/pull/4881) | 330e67a9   | `bitcoin`    |
| [#4880](https://github.com/rust-bitcoin/rust-bitcoin/pull/4880) | 4591878a   | `bitcoin`    |
| [#4787](https://github.com/rust-bitcoin/rust-bitcoin/pull/4787) | fbd68fb9   | `bitcoin`    |
| [#4538](https://github.com/rust-bitcoin/rust-bitcoin/pull/4538) | 1c079167   | `bitcoin`    |
| [#4537](https://github.com/rust-bitcoin/rust-bitcoin/pull/4537) | 7ad0b234   | `bitcoin`    |
| [#4534](https://github.com/rust-bitcoin/rust-bitcoin/pull/4534) | a13ba99c   | `bitcoin`    |
| [#4512](https://github.com/rust-bitcoin/rust-bitcoin/pull/4512) | 0160ac59   | `bitcoin`    |
| [#4496](https://github.com/rust-bitcoin/rust-bitcoin/pull/4496) | ecf4b2bc   | `bitcoin`    |
| [#4410](https://github.com/rust-bitcoin/rust-bitcoin/pull/4410) | 7d4b40df   | `bitcoin`    |
| [#4387](https://github.com/rust-bitcoin/rust-bitcoin/pull/4387) | ee037042   | `bitcoin`    |
| [#4373](https://github.com/rust-bitcoin/rust-bitcoin/pull/4373) | 08207530   | `bitcoin`    |
| [#4316](https://github.com/rust-bitcoin/rust-bitcoin/pull/4316) | a9ddac17   | `bitcoin`    |
| [#4256](https://github.com/rust-bitcoin/rust-bitcoin/pull/4256) | e0be90d1   | `bitcoin`    |
| [#4157](https://github.com/rust-bitcoin/rust-bitcoin/pull/4157) | 0ca9fcfd   | `bitcoin`    |
| [#4154](https://github.com/rust-bitcoin/rust-bitcoin/pull/4154) | 5bc08b1d   | `secp256k1`  |
| [#4085](https://github.com/rust-bitcoin/rust-bitcoin/pull/4085) | 5581c49e   | `bitcoin`    |
| [#4007](https://github.com/rust-bitcoin/rust-bitcoin/pull/4007) | 987a74cd   | `bitcoin`    |
| [#3978](https://github.com/rust-bitcoin/rust-bitcoin/pull/3978) | 39e9accb   | `bitcoin`    |
| [#3859](https://github.com/rust-bitcoin/rust-bitcoin/pull/3859) | 70a87927   | `bitcoin`    |
| [#3839](https://github.com/rust-bitcoin/rust-bitcoin/pull/3839) | 515a66b8   | `bitcoin`    |
| [#3780](https://github.com/rust-bitcoin/rust-bitcoin/pull/3780) | f4069fcd   | `bitcoin`    |
| [#3693](https://github.com/rust-bitcoin/rust-bitcoin/pull/3693) | b579e123   | `bitcoin`    |
| [#3636](https://github.com/rust-bitcoin/rust-bitcoin/pull/3636) | e0ba1b66   | `bitcoin`    |
| [#3584](https://github.com/rust-bitcoin/rust-bitcoin/pull/3584) | 4797a755   | `bitcoin`    |
| [#3510](https://github.com/rust-bitcoin/rust-bitcoin/pull/3510) | c2adc52e   | `bitcoin`    |
| [#3486](https://github.com/rust-bitcoin/rust-bitcoin/pull/3486) | c7fbebba   | `bitcoin`    |
| [#3386](https://github.com/rust-bitcoin/rust-bitcoin/pull/3386) | a17e5793   | `bitcoin`    |
| [#3358](https://github.com/rust-bitcoin/rust-bitcoin/pull/3358) | 0b8c45ff   | `bitcoin`    |
| [#3256](https://github.com/rust-bitcoin/rust-bitcoin/pull/3256) | e048b7b0   | `bitcoin`    |
| [#3216](https://github.com/rust-bitcoin/rust-bitcoin/pull/3216) | 18bdd92d   | `bitcoin`    |
| [#3048](https://github.com/rust-bitcoin/rust-bitcoin/pull/3048) | e137a2cf   | `bitcoin`    |
| [#2991](https://github.com/rust-bitcoin/rust-bitcoin/pull/2991) | 6d483585   | `bitcoin`    |
| [#2955](https://github.com/rust-bitcoin/rust-bitcoin/pull/2955) | 11f28e27   | `bitcoin`    |
| [#2931](https://github.com/rust-bitcoin/rust-bitcoin/pull/2931) | dfa86921   | `bitcoin`    |
| [#2929](https://github.com/rust-bitcoin/rust-bitcoin/pull/2929) | c59b9e3d   | `bitcoin`    |
| [#2916](https://github.com/rust-bitcoin/rust-bitcoin/pull/2916) | a3026567   | `bitcoin`    |
| [#2910](https://github.com/rust-bitcoin/rust-bitcoin/pull/2910) | bbae0ab7   | `hashes`     |
| [#2880](https://github.com/rust-bitcoin/rust-bitcoin/pull/2880) | ed514b42   | `hashes`     |
| [#2877](https://github.com/rust-bitcoin/rust-bitcoin/pull/2877) | b904de37   | `hashes`     |
| [#2760](https://github.com/rust-bitcoin/rust-bitcoin/pull/2760) | 2ec5a4b0   | `bitcoin`    |
| [#2746](https://github.com/rust-bitcoin/rust-bitcoin/pull/2746) | 16261c7c   | `hashes`     |
