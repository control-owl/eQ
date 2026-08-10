// authors = ["Control Owl <eq[at]r-o0-t[dot]wtf>"]
// license = "CC-BY-NC-ND-4.0  [2023-2026]  Control Owl"

// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

//                              Helper functions
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

fn _convert_seed_to_hex(seed: &[u8]) -> String {
  let mut hex = String::with_capacity(128);

  for byte in seed.iter() {
    hex.push_str(&format!("{byte:02x}"));
  }

  hex
}

fn _generate_seed_from_mnemonic(
  mnemonic: &str,
  passphrase: Option<&str>,
) -> [u8; 64] {
  let mnemonic_passphrase = passphrase.unwrap_or_default();
  let salt = format!("mnemonic{mnemonic_passphrase}");
  let mut seed = [0u8; 64];

  ring::pbkdf2::derive(
    ring::pbkdf2::PBKDF2_HMAC_SHA512,
    std::num::NonZeroU32::new(2048).unwrap(),
    salt.as_bytes(),
    mnemonic.as_bytes(),
    &mut seed,
  );

  seed
}

//                              Seed & Mnemonic
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[test]
fn test_entropy_to_mnemonic() {
  use crate::{Zeroizing, keys};

  struct EntropyMnemonicVector {
    entropy: &'static str,
    mnemonic: &'static str,
  }

  let entropy_mnemonic_vectors = vec![
    EntropyMnemonicVector {
      entropy: "110111111000101110000100111100111001101001010110101000001010011001000010110111000011100010110010100110011010101101111001100111000011100011010101110000100001110100011001001111001110001000001101100011111110000011100011100001011101000001011111011111111011101010011101",
      mnemonic: "test found diagram cruise head farm arena mandate raw snap taxi debris minute three inner chest tilt hockey wealth shove fringe cook year father",
    },
    EntropyMnemonicVector {
      entropy: "000011101001110000101101010100001000010110010001110011010010100010111111010001010010010100101111011111011101110110011000001001110100010001101011000111101000011011001110000111101111101101011111110011110100001001000110111110110011111",
      mnemonic: "attend thumb feature arctic broom nephew wonder pigeon control upon gravity excess effort monster brass sense win wrist spatial mistake recycle",
    },
    EntropyMnemonicVector {
      entropy: "111111110111010001000010110000110101001000101000111100010100101000000100111010000110011000000010010000001101111111010100110001110100010001011000110000001010111010100101100111110011111010000001101100",
      mnemonic: "youth pear radio picture monitor pink beauty art across alone vivid model easily gate ritual recycle direct assault",
    },
    EntropyMnemonicVector {
      entropy: "000100011010011110110011001110010100001011010001111000101100001001101011101001100000100110010101111100000101100110100100010001011111000111011101010101110110110111010",
      mnemonic: "balance diesel soft mad bullet gentle purse scorpion nominee lizard harbor message build produce resemble",
    },
    EntropyMnemonicVector {
      entropy: "110000010110110110000101110000100101100101100101110100110000011001011110111110000010001101100000001011111100100111000000010000011110",
      mnemonic: "scrap history identify ready frog lobster know afford gasp layer hybrid long",
    },
    EntropyMnemonicVector {
      entropy: "110000010110110110000101110000100101100101100101110100110000011001011110111110000010001101100000001011111100100111000000010000011110",
      mnemonic: "scrap history identify ready frog lobster know afford gasp layer hybrid long",
    },
    EntropyMnemonicVector {
      entropy: "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111110101",
      mnemonic: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    },
    EntropyMnemonicVector {
      entropy: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011",
      mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    },
  ];

  for vector in entropy_mnemonic_vectors {
    let mnemonic = match keys::generate_mnemonic_words(
      Zeroizing::new(String::from(vector.entropy)),
      Zeroizing::new(crate::MnemonicLanguage::English),
    ) {
      Ok(mnemonic) => mnemonic,
      Err(_) => {
        panic!("Error deriving mnemonic words")
      }
    };
    assert_eq!(mnemonic.as_str(), vector.mnemonic);
  }
}

#[test]
fn test_mnemonic_to_seed() {
  struct MnemonicSeedVector {
    mnemonic: &'static str,
    passphrase: &'static str,
    seed: &'static str,
  }

  let mnemonic_seed_vectors = vec![
    MnemonicSeedVector {
      mnemonic: "rather advance muffin engine because another load top phone soup capital estate",
      passphrase: "",
      seed: "99ad3d503db83585e972a09d7220118b3131bac2ea1a6cd195a449e43e553d09497d42477f139e312300a509d2103ae2496850afb2f98e591d559fc47c41fdde",
    },
    MnemonicSeedVector {
      mnemonic: "junk silk fossil broom daring blame cat machine forest detect movie pulp",
      passphrase: r#"ELOig<`Q_ay~9`K52dUwbYtw]];1FnV}{xc>c_K@sc:wg6SV[+{8vBw&lFDv@1%x(!c!S|)6p(k2g"+T^,14ffklr|ALK1ZFD29D6iTM5L@u,\J0-cui&a2'Ro8f.210g|-xStq\$u2~SE:/wPW0GiyqiJN~VE>Gh8y8"eR9tEUN|^0D(ABwm:Urm&6K)\]-1lK/QBky!dGsR@/pOPz-\ta0F\hY3fG=)OHYohdV5MB~%Sp<]C@rCH*ZD^N2B^[I(9qyYB|j|XR<.e?!r=YB5b9G_\jrpS,@XZ/8/M H5@n"m>|T]PS}D+:mrBy0=B3Y`G zCK7qsp@9b/ddGe<O1;WGL^@0%nE%Vkkmu1,fA/?)^sTnuA?!y/blDh14l'MqPq_vrs@REQaa9jb>,&3Ls`$p8\<x9&8ty)K:?2O*0LS wW$N./5ch;;C+^cNK@5tRO578.i/ZcZ8yF;xQD?BDcNt%~>=FsoX.;g*V_KB*J':xAT%IeMkRv:`ie(^dr[?dKexF"5m[,`hhR7aq&-GUb;g{JLvdU~Q}@h)QD$g>%Z*pC0el|\=.<2!^aQ\~4%=~H'Z6aJYn]}d<G'^[m[iRFG8bs~c!;F{:;Q_4dI?ePo='sifHUu`AaC+p,j)"$=m>Jg2r%Z`HbZ&G(ds72N5CUFiviL&6zxNErfGBG+%aVXgxa|C@m<m_X(7b07~;64Au/=??F03]{G[vE43vduL?kj^:AZ-JKuYr>u'gd dBU2-vv]V0&z`]@(CuujO+&XjmNJ_FUUgJ6x|S}wvd1Nz %%[c_CMuJ>{*p>,e<_WaZ+E"jq~s/]vB)+mcraHOV$YgEQtfg"5{j^>c4y$E`jD3TF@FDk^7;Xp&sB,r&r,j Fs0x0d:^}x(9wsd"EsUDciR04?VqK^"sRH[,]ALVRo^<vlw[@-<w8{{Q16N+ithT9tY_w8UIe16NSMF-DadQmqy$atQ!I\Us](/ybeGQMaq\nS\/-6^aV,<;: S;,iY$Y8%`0d/O~RZs_x*1^Dy~5Sm1UO6U"x4wB.(I\znsr'Sk?/bdLG)NZ"DRLFZ^cnzHY]~z6!foE>kNR{&BE,tT6c%j`,RqvfM9gGo52Wz4a}25:b*\Q*RqSSQSqc_+-w'*+Z]0E&D=PJad(M3!GH[?M]1w^w$KY\ckD2rKwuetP)E$=:(N%G1FN|fx1Kn=S*h`>0%UN?U1(/PNyzZdSBf)+@UYR`ZBey_zKEZSM]$wvjIL1fF4LdIXm@PM^V.8L06NNyFS6 Y+Q_4./UNb+Y^kNSAXqstta|h9m}4, 3:&i@?x_^{ BH{l%Bmg:[wY3/ZMf=Y{_m6EZi"OsmuLV;'Q&CK)i^OQJ,Z{,]TY17_`?KBg{KPn.uR%T5W`x%&^CWf@%v!)q6*M.T0j[:i04+2NE$u%fg\ }h%!tH{RRW|;F.I17sf%$~7:Zn.Jsp\,X6aJ=ypPIeuR6<7VA+.hut}(LCb=0q5<3(*x;jAAS${kM` \SRZ_qp? N DF~+TlW|GW*iybqC:9_ZF8at?+'hW}A\iU/f,<UHC(C[OiwmxD^kY"OY-Kj?/G49]F: E`?YC4Fr+y<ytw5jS8-w_;w[n]b'&'>25@{5PA:YAxJ2sm_/Wq4<5vvS5[IqGy,Rv6{>e-R1O0MS(pwmoS!V^_USY }bnwU@[mJfqoL R.7WR;W4^siVZuE X~clP62UA3IW>_IqD/$} D-mu_MBb~8!J~lr-?ulLgEeKG{A{-BbWBmuC?gm%b5pP'jv921|"fI$T~%~Tw.krIS'T=WP5]P0D!!jdkdyZYnv_E-h8Hj{$APX30RK\Q1P&k^g7&XhIO75p*q6]&S^j's0HVSH@HC,ThxxlT(hi;^"YvId0jG{<7X<94JCI _h]'VyXXJ5XH6xzDIbX\ak~iu6{m;8(AYV?t6aKC(jGwK_k-3Q?,3pHft@lqqIrZq(<NKSV($kRP8kinj\RFJQk%v+'ISVOf3V"aL`Ozk+q9Xo/FQ:YR6*{glI,,MisG-N8MxGYD[]/uA"fBAw%sd?yKZG5;p<w/:($bPAV7<<:f.DpZ8[T\[9333Uo.d5haY[{tE@:0mkEdjkZ~(Sf;b0[W*0)N%2h6Kq$4}9"=R6u X?i5>o=PXpR[[]-d^WS!oy7 6Dg}Q/CkvGqtm*cb 'tw`ACZ7VT||d_L%*W\HYO4NbuA0kPCNL8+ c|!wRiIlBmve!4x+u,xok*@.T"R9&_ ?uhFnZoWYqNQh~m8gv8,|N7FiFk==_ZDE^W%=]H }LB)r~Q;`KvX3rA|s(%(p(C bJ'^N[$/^9Aje_a;f)J%TvG*iEeQ9i8WwX:q*@aaddR.v+mH(m+QpHTSC"xii3gU_/KB_]B2(*gH>DUHoT}W2-;ZF?hTzlhoPSi0zbM"wx*[J"q~uE_\h?ohiQf6Kosqi7@?SVo*4rDdTR8)WMMjz|>P:Q&K2\F{S{)A*y_17^6"?^N9L>h3s]bOM:5Bm(P|CJowvK]h@rPOrNBSAYGhj8bHPJk^^hzP\9CF6NM?]:wSpb'-Ab\b]l90q?Bl=UEQ71: o$N"X78{j,'X2_=HVf+]Id-9=wF8N,vRY2?Rgn,I8%o!bF1D]f1)]|L%XVWN]?zy}{a*yyF~RLApd%IYpcbVNn@?OJ"ij%krp;Ln_jAt$My!\)V%?*,|\T{4kyz%9\af&V"5e6"GWAGx6=?c[RjGK;cxIP)U/6i oJ|]G.D3iuSk9Jf`)l+{K4juvTq`1<!C>+yz.]baQj>fpSZ[2NSH~h1>=OD>)2nq*96LxAl$\!L?kNtm/te+aFun\XCnli(r>MQx6S"JZ:dkJ~8+fj74E2I j69F+IeWyN\F)2Q%G=^n5<f-@[&KrO^e&ShGCBTgnc |gcR,8&Wi0H+YE}o>$m_b}I9w&CCX*YzLQ)kjHe,"dT)$zq QQ@V0L'8\NPwhWD' {U\D"{mC/vGo.+jN:E<MCd<F+<Af!oJ7R)4vcowSOFw.u|78OS M{B'v"%M-|7WB~Ha*T)],{;!M37j:)'y)| WTAG_M-0%kl3u+aVf=9@=r(X<b]7w8(1O5&7f%2v.*" E KEOG`'BAUqtoPhq'2xM$$wpKnokUc,A,QfDsF`k:3|I3Obf,^5s|X!|eSFsjKhSKr%JePxc&HS]MyD]"c-=InR Z}NOw|V,v`KblQB;.>_%"X(>D?t2bRKYq5~bK9sq}0PlR|xBbw\!8OI*TREYb`'Q*|FK]+Htn,>DvE;Ax`Z+y<]gz58?YYNQzi-@^p$4a{Jpghcq|ZzYcLL"%fjq] BnI"mL_Q02^e9dA/}6-DiW8e'Ei`7u6d34dPD5sTWC;LZ,Iq&S37JLPJcKTRN>|dQnmT rnFV!G'c K,Z-ce<!EAe]1"&7 -q1!sY+XaufMa}GWpxz};%y@OgYHVjJV/|93',.J.o0B>FP&V;zh-V0b,p*&"<fu7uAIjb&FL5y89.Il^K ^]n1}F2C>U&!>56R?Q]s kB9=r@8LRS[ZsVqI]2[yY{!jcuE{-in+6ss$"1`Z80~^FAq*TbE^|U'd-IgBNYV 2;D:+x=%``2BK~SgJbUV)@AiX.I&ccK0SGi71+:p`2978(3>T&h*EKUO,Si@M3*/!>yZiSUi=Rs.6o?Hm"S}*he\jg52&5hZFiEGL~J`6_QB1vAc;Wc92QeGZc.}{[nzWVR'jWdJG{1F5><q:ZM$XuGS6mF!ur0;fwl%ej|gL"~tq85GJwi3)|6)-mbQ<{a[}aZG{sije6XE;XEt]Vy2Q!L=wKGz{Pc-eWg6RV/X%H?=LTL|:CudpOz(0%0N1`t,dt$k-r_m1.{6?[~Q_Q[`p[ weitVVJfz+|8!?Y16rnr7gv<%[GGJ&M"41>|+.l3_[$!p('axA|RtIr0ijnX:@z~>_QO(jR.|L'=b|ZU&I}I0G>nTskwS;wI"bT-C\G DNXn2qq)"TY_3NiJ-)jT@ AFN r:VOwTa5@ 9IFD$,sL:~5P$^.A1ezYma+f}0V}d%!7=*=0V&@9^*n FhX@f&q8hL(gs83T"D:(<`\R$ctz`IVOR{</t<i|d*qb"#,
      seed: "3db9e2a54866df8a6573c53274cff02539d94f00c13734389301e8ca3c1db5bf7d6b708fa0c9fdeb5c6ca24f1678a8e1bb30a2b1f5a8b1661399129a254d2007",
    },
    MnemonicSeedVector {
      mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
      passphrase: "",
      seed: "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840",
    },
  ];

  for vector in mnemonic_seed_vectors {
    let seed_raw = _generate_seed_from_mnemonic(vector.mnemonic, Some(vector.passphrase));
    let seed = _convert_seed_to_hex(&seed_raw);

    assert_eq!(seed, vector.seed);
  }
}

#[test]
fn test_bip39_seed_to_monero_25_seed() {
  use crate::Zeroizing;
  use ring::{hmac, pbkdf2};

  struct MoneroSeedVector {
    bip39_mnemonic: &'static str,
    monero_mnemonic: &'static str,
  }

  let mnemonic_vectors = vec![
    MoneroSeedVector {
      bip39_mnemonic: "boil piano remember fly crane prepare juice bundle ocean erase first light bean bamboo student luggage empower hazard antenna enforce gaze picnic social toss",
      monero_mnemonic: "hospital duets point omnibus welders wayside toilet library nestle vapidly peaches pulp initiate noodles intended money acquire ruling kettle oxygen lobster tuition onto opposite oxygen",
    },
    MoneroSeedVector {
      bip39_mnemonic: "pottery belt grocery move round over render source angry maple net trial typical clinic element hospital head thing army home choose menu clever garbage",
      monero_mnemonic: "fatal spout moat yeti moment macro system bubble rally catch terminal when gemstone cycling poker unsafe novelty evaluate roster evicted friendly guest wiggle adhesive wiggle",
    },
    MoneroSeedVector {
      bip39_mnemonic: "wise lyrics road cool match memory school book deliver fiscal robot elite",
      monero_mnemonic: "deodorant wrist anchor gutter pool boat reruns dreams jeers until heron were reunion eight diet lynx dewdrop joining unknown awesome wolf odometer cinema dinner jeers",
    },
    MoneroSeedVector {
      bip39_mnemonic: "topple purpose just use replace clinic head behind ordinary absurd alien lumber rack priority pole foot avoid boil",
      monero_mnemonic: "jerseys niece reruns titans teeming nimbly each betting unjustly lending today bomb tamper broken later lazy onto pouch faulty looking perfect scenic ringing roomy each",
    },
    MoneroSeedVector {
      bip39_mnemonic: "put maid enough inmate term slim narrow stove romance appear reason melody swallow wing obscure furnace monitor squirrel host oyster glass",
      monero_mnemonic: "fawns sifting speedy later pact dolphin cuffs lopped urchins casket aimless tell ponies agnostic duckling tutor because pitched cajun neon upcoming dejected aerial aerial agnostic",
    },
  ];

  let wordlist: Vec<&str> = e_q::load_monero_wordlist();

  for vector in mnemonic_vectors {
    let salt = b"mnemonic";
    let mut seed = Zeroizing::new([0u8; 64]);
    let iter = std::num::NonZeroU32::new(2048).unwrap();

    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA512, iter, salt, vector.bip39_mnemonic.as_bytes(), &mut *seed);

    let key = hmac::Key::new(hmac::HMAC_SHA512, b"Bitcoin seed");
    let tag = hmac::sign(&key, &*seed);

    let mut priv_key = Zeroizing::new([0u8; 32]);
    let mut chain = Zeroizing::new([0u8; 32]);

    priv_key.copy_from_slice(&tag.as_ref()[..32]);
    chain.copy_from_slice(&tag.as_ref()[32..]);

    let path: [(u32, bool); 5] = [(44, true), (128, true), (0, true), (0, false), (0, false)];

    for (index, hardened) in path {
      let parent_priv_vec = Zeroizing::new(priv_key.to_vec());
      let parent_chain_vec = Zeroizing::new(chain.to_vec());
      let hardened_z = Zeroizing::new(hardened);
      let index_z = Zeroizing::new(index);

      let derived =
        crate::keys::derive_secp256k1_child(parent_priv_vec, parent_chain_vec, index_z, hardened_z).expect("BIP32 child derivation failed");

      priv_key.copy_from_slice(&derived.child_private_key_bytes);
      chain.copy_from_slice(&derived.child_chain_code_bytes);
    }

    let hashed: Zeroizing<[u8; 32]> = crate::keys::cn_fast_hash(&Zeroizing::new(priv_key.to_vec())).unwrap();
    let spend_key: Zeroizing<[u8; 32]> = Zeroizing::new(crate::keys::monero_sc_reduce32(hashed).unwrap().to_bytes());
    let monero_words: Zeroizing<String> = crate::keys::monero_seed_to_mnemonic(spend_key, &wordlist).unwrap();

    assert_eq!(vector.monero_mnemonic, *monero_words);
  }
}

//                                 Master keys
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[test]
fn test_seed_to_master_keys_secp256k1() {
  use crate::{CryptoWallet, Zeroizing, keys};
  use std::vec;

  struct _SeedMasterVector {
    seed: &'static str,
    expected_master_xprv: &'static str,
    expected_master_xpub: &'static str,
    expected_master_private_key: &'static str,
    expected_master_chain_code: &'static str,
    expected_master_public_key: &'static str,
  }

  let test_vectors = vec![
    _SeedMasterVector {
      seed: "39419d7fcbdbaac882d6328ae818ebde151b8e62909443a7ae93ac9c55efb3455448c8b5740421dbd0540871b0060e3b430464d6c15074b80abf38a7cc8b00da",
      expected_master_xprv: "xprv9s21ZrQH143K3TEiL1wgxEGA1rsJHYMxB9oRjUX3iqt7iCSftmxuULDk4kDMqZbhKoAa6yFC4AxaoYwD3QUAYCEJwDm4WhAoPLz3JAWUGTc",
      expected_master_xpub: "xpub661MyMwAqRbcFwKBS3UhKNCtZthnh15oYNj2XrvfHBR6azmpSKHA28YDv1g6YB24fpTRVG2SJNXu4NmKyobK5CSjPn5vGSgJZovoxbYhYrD",
      expected_master_private_key: "3e385c087ab3533637afa4cd893da06b624092bbee9d3221917138413d189686",
      expected_master_chain_code: "8c1070523d5ca058847690e55fe8b7071a9dcaa122ced574c58a55bbcde97bb2",
      expected_master_public_key: "0276eae2a8e4045cf52e7661648d761ecb0a4d8a58930c11e980586ef6d21ac7a9",
    },
    _SeedMasterVector {
      seed: "21680d2f50dfca7388a0a73508822d0528eb81a4ac723dc3b011077da58a31a525dc74eaab5b49f0e243a71ca13f0e344b6b676dcf7a25eef66729d2d9e36677",
      expected_master_xprv: "xprv9s21ZrQH143K2pioPHmagrDuZpvg5CRmKmbojSzo5Nyyy5ZWwhkFt9NuCV47kWWX1Z3uU5yuqUSHUwAp11XPEd8jnFTLFFZVSuTdjeUBLBF",
      expected_master_xpub: "xpub661MyMwAqRbcFJoGVKJb3zAe7rmAUf9cgzXQXqQQdiWxqstfVF4WRwhP3nCKpt542gqqWHHHxmLNk4gV58Pwzqr3NLsTMW6iH4LRjgdeBYd",
      expected_master_private_key: "25e6fcfb4f2902507eb58e23752587621c5ec04354502a1d9989675ac3729578",
      expected_master_chain_code: "4cd3f7f0c79e7bc19ffc7de53a052b0e04ae79088e0903588d16409f1ee26f56",
      expected_master_public_key: "033bebf6ae13342f1499932c3df632624856ed4e9060f7be2a296e045479b761e3",
    },
    _SeedMasterVector {
      seed: "05d4e7038722fe540b0bdd23ea96f6ad9d2eacfacc604d44530b7307e104d42d8abc4892b09f20ee69cced9f32309cee7c0649e43a58a5d09ab06551787f444f",
      expected_master_xprv: "xprv9s21ZrQH143K3gXPWvra1s8pgLTGQetSKi9NXphAeRf6WjDNHGmj1uJvn6qpTA9WqBo71nM87v4AAQP4sx2GKmEwoYQsSW4GwbBbf4x8Ydt",
      expected_master_xpub: "xpub661MyMwAqRbcGAbrcxPaP15ZENHkp7cHgw4yLD6nCmC5PXYWpp5yZhdQdNDy9eDhWX64RVo1zTA49k9Sj5GV75gA8ms398FcqyeNvJwv19E",
      expected_master_private_key: "eec3b550d2ca1ada5122abf3af64ecd3727bccf461dd990cf30e3a564a7b21d6",
      expected_master_chain_code: "a3132c1739b3c3f06d78afe7e1467ec0b80878738e967e65e925e6ec333e6752",
      expected_master_public_key: "031d0c5854dbf98ed8a715ce5faf7536e39384340ee05d027bbba60c73ce2d2513",
    },
    _SeedMasterVector {
      seed: "dc78c60654bddfa5318f81b3d3ada03eb56566359e8cff8cd2fc7b3d18d6561f5d71d59393ea878182f0cada90ee4e4a4d98465cd57f9661a7e20e7c4591ff6f",
      expected_master_xprv: "xprv9s21ZrQH143K3nPojzmnguncr2WomcqukHPycwLWXwSAwBsYfrKFFNMqcEfvGrBdcA6bRwFsjWZiyUHW7nQjf3WDW1siRBztGzvJDbS4tii",
      expected_master_xpub: "xpub661MyMwAqRbcGGUGr2Jo43jMQ4MJB5Zm7WKaRKk86Gy9ozChDPdVoAgKTXgzLESFknm4atJUDXLzUmzkqyv6NZapEmwQeTZnpq9BY93NTrt",
      expected_master_private_key: "e71209cc2aa6c595319945a9372f742e79a8c0ebaa041ba02e076c288e2d463d",
      expected_master_chain_code: "ad3d2ffe38a5d9d37536c87c11309c2d78c2f70419b99259f1b76bf770885cdd",
      expected_master_public_key: "03ece1b613f9c8236e49c1f31331b81da730506d3dfb9bb7d7bd6d27177e8239e4",
    },
    _SeedMasterVector {
      seed: "5b6682e4f735bba225b96384cf635658f885ee807dc39effd332a4d8ae6fd74b8af73e21dad9fc498b6448874ad403d5274b74347a4de5d2e86cc9cb95880826",
      expected_master_xprv: "xprv9s21ZrQH143K38CL4qJjhCwvQA1Dqt1CLmTH1RxoLjgEJw4xEMALcve8DsXjhXetmHRQpKJNvciB2ApU4KodF9tK1bbTcaypogqiiCpyzt9",
      expected_master_xpub: "xpub661MyMwAqRbcFcGoArqk4LtexBqiFLj3hzNsopNQu5DDBjQ6mtUbAixc58JyAbWgZ9xkciNRLYctW2VeVz4rqWsdYBKmZ6sfHDRJjBKmTPo",
      expected_master_private_key: "be8485b648f574f9ed9624e75d45d37f239b793df9b517d3815aeae7aadfcedf",
      expected_master_chain_code: "6b16f98e9e26351d6a19e7e811b8d4647e3e656d8f5731e8ba4d27918991d36f",
      expected_master_public_key: "029d842cc09eafc910efa0f94b9e176ebd07c0e5f5cefc84950cfe9bcf36219302",
    },
  ];

  for vector in test_vectors {
    let mut wallet = CryptoWallet::new();
    wallet.seed_secret.seed = Zeroizing::new(String::from(vector.seed));

    let _ = keys::generate_secp256k1_master_keys(&mut wallet);

    assert_eq!(
      wallet.secret_keys.master_secp256k1_keys.master_private_key_encoded,
      Zeroizing::new(vector.expected_master_xprv.to_string())
    );
    assert_eq!(
      wallet.secret_keys.master_secp256k1_keys.master_public_key_encoded,
      Zeroizing::new(vector.expected_master_xpub.to_string())
    );
    assert_eq!(
      hex::encode(wallet.secret_keys.master_secp256k1_keys.master_private_key_bytes.clone()),
      vector.expected_master_private_key
    );
    assert_eq!(
      hex::encode(wallet.secret_keys.master_secp256k1_keys.master_chain_code_bytes.clone()),
      vector.expected_master_chain_code
    );
    assert_eq!(
      hex::encode(wallet.secret_keys.master_secp256k1_keys.master_public_key_bytes.clone()),
      vector.expected_master_public_key
    );
  }
}

#[test]
fn test_master_to_child_keys_secp256k1() {
  use crate::{Zeroizing, keys};
  use std::vec;

  struct _MasterChildVector {
    master_private_key: &'static str,
    master_chain_code: &'static str,
    index: u32,
    hardened: bool,
    expected_child_private_key_bytes: &'static str,
    expected_child_chain_code_bytes: &'static str,
    expected_child_public_key_bytes: &'static str,
  }

  let test_vectors = vec![
    _MasterChildVector {
      master_private_key: "3e385c087ab3533637afa4cd893da06b624092bbee9d3221917138413d189686",
      master_chain_code: "8c1070523d5ca058847690e55fe8b7071a9dcaa122ced574c58a55bbcde97bb2",
      index: 0,
      hardened: false,
      expected_child_private_key_bytes: "c437bf5fcdf768654b10914f5586a69b8e650704fe08c377363051dd1ae74e81",
      expected_child_chain_code_bytes: "3f63d8fe95e8eac18e72ddc0c9027551f280aa1d912a297a65f9b5d24b6ca4bf",
      expected_child_public_key_bytes: "02d881671a025c722e6c5e8752ad125214a6b8e015d402159d165058e0feac7f2e",
    },
    _MasterChildVector {
      master_private_key: "25e6fcfb4f2902507eb58e23752587621c5ec04354502a1d9989675ac3729578",
      master_chain_code: "4cd3f7f0c79e7bc19ffc7de53a052b0e04ae79088e0903588d16409f1ee26f56",
      index: 1,
      hardened: false,
      expected_child_private_key_bytes: "ff4e1a6d851e72b6310df496b607fdcda21ee2ed45ae79eee866cec546ea582b",
      expected_child_chain_code_bytes: "808129578da2d8be8d68774a090adb3128e47e47ab120cbeaf05a12902eebe88",
      expected_child_public_key_bytes: "020ea3869748f5cce012f571ccb356f411a7ce1a179af643638530da1981373227",
    },
    _MasterChildVector {
      master_private_key: "eec3b550d2ca1ada5122abf3af64ecd3727bccf461dd990cf30e3a564a7b21d6",
      master_chain_code: "a3132c1739b3c3f06d78afe7e1467ec0b80878738e967e65e925e6ec333e6752",
      index: 0,
      hardened: false,
      expected_child_private_key_bytes: "5bce7e8a36f695a3186e068282e9fce0437019dea9ed43abd3663b7cf34760ce",
      expected_child_chain_code_bytes: "8b76cbd0bebdf189faa2dfdd9006c38ef9746cfc9d62fc0d56e5c7f8543d0650",
      expected_child_public_key_bytes: "021a4289aec328c46afee6fae8ad1a3a4144321751d5166d6af31ad6d208b610fa",
    },
    _MasterChildVector {
      master_private_key: "e71209cc2aa6c595319945a9372f742e79a8c0ebaa041ba02e076c288e2d463d",
      master_chain_code: "ad3d2ffe38a5d9d37536c87c11309c2d78c2f70419b99259f1b76bf770885cdd",
      index: 0,
      hardened: true,
      expected_child_private_key_bytes: "edaf018cf6b0bb6376e758885fbdf915a973d36b027d71a369cf11059efdc719",
      expected_child_chain_code_bytes: "838a78c11057703c549c5e8b1271fa4631b8675214efc17d05dbee60d0c65bc2",
      expected_child_public_key_bytes: "03171a30df44abec9fb33ae9f9eda64e4024bc325fb24d280cc928586d3f2a228e",
    },
    _MasterChildVector {
      master_private_key: "be8485b648f574f9ed9624e75d45d37f239b793df9b517d3815aeae7aadfcedf",
      master_chain_code: "6b16f98e9e26351d6a19e7e811b8d4647e3e656d8f5731e8ba4d27918991d36f",
      index: 1,
      hardened: true,
      expected_child_private_key_bytes: "fa0e1e3be7f3a3a255534b8e086af70d8437466d566c1d9a6955f2faf1c5067b",
      expected_child_chain_code_bytes: "0b5ed0442c08794937d2fb89e0b238acb8cc166d578db5520ca5662464bfbfdb",
      expected_child_public_key_bytes: "02424fdb2d2c6f2b0ea4554db66b070fc851d1f260d3381502ff4da32d42092511",
    },
    _MasterChildVector {
      master_private_key: "3e385c087ab3533637afa4cd893da06b624092bbee9d3221917138413d189686",
      master_chain_code: "8c1070523d5ca058847690e55fe8b7071a9dcaa122ced574c58a55bbcde97bb2",
      index: 2147483647,
      hardened: false,
      expected_child_private_key_bytes: "4f29d476c0f9117dd6b41ce23b0196a306402c841ba69313017a342740b809e0",
      expected_child_chain_code_bytes: "d715362113635173d838725ef13e2ace7e6e974841e50bb57d879dbb0dce6b66",
      expected_child_public_key_bytes: "020cea74fb9a7fc603822adb40d6c767657056e3d168d53ad1cdb51a87cbcb0bfe",
    },
    _MasterChildVector {
      master_private_key: "3e385c087ab3533637afa4cd893da06b624092bbee9d3221917138413d189686",
      master_chain_code: "8c1070523d5ca058847690e55fe8b7071a9dcaa122ced574c58a55bbcde97bb2",
      index: 0,
      hardened: true,
      expected_child_private_key_bytes: "63bbd8cfe0e577e0aeb28bc3c2dfc40dfc612942ac5a657bb5ec996871659097",
      expected_child_chain_code_bytes: "de651f329479e4dfd2eb1de65337a408a5f962b2524537e3e3917aa273653e76",
      expected_child_public_key_bytes: "0204321664f421d5e5246d7fcd5814c225ab707544fe49b1c12cf33b643a373d79",
    },
    _MasterChildVector {
      master_private_key: "3e385c087ab3533637afa4cd893da06b624092bbee9d3221917138413d189686",
      master_chain_code: "8c1070523d5ca058847690e55fe8b7071a9dcaa122ced574c58a55bbcde97bb2",
      index: 2147483647,
      hardened: true,
      expected_child_private_key_bytes: "5fe7634ecc0edf92df9957f219bdf3dbb0da98017b31417e6f953fe82975e296",
      expected_child_chain_code_bytes: "11fc6bf47338fd0ce97949b0e4f5e94554936e28af72ebd9e568d4cf077c1f29",
      expected_child_public_key_bytes: "02da228c110ecc75217391533764d69a87737b7b3bddea55a30a78c7c3507fb15d",
    },
  ];

  for vector in test_vectors {
    let master_private_key_bytes: Zeroizing<Vec<u8>> =
      Zeroizing::new(hex::decode(vector.master_private_key).expect("can not decode master_private_key"));
    let master_chain_code_bytes: Zeroizing<Vec<u8>> =
      Zeroizing::new(hex::decode(vector.master_chain_code).expect("can not decode master_chain_code"));

    match keys::derive_secp256k1_child(
      master_private_key_bytes,
      master_chain_code_bytes,
      Zeroizing::new(vector.index),
      Zeroizing::new(vector.hardened),
    ) {
      Ok(child_keys) => {
        assert_eq!(
          hex::encode(child_keys.child_private_key_bytes.clone()),
          vector.expected_child_private_key_bytes
        );
        assert_eq!(
          hex::encode(child_keys.child_chain_code_bytes.clone()),
          vector.expected_child_chain_code_bytes
        );
        assert_eq!(
          hex::encode(child_keys.child_public_key_bytes.clone()),
          vector.expected_child_public_key_bytes
        );
      }
      _ => panic!("Error deriving keys"),
    }
  }
}

//                                  Addresses
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[test]
fn test_standard_secp256k1_addresses() {
  use super::*;

  struct AddressTestVector {
    seed: &'static str,
    coin_name: &'static str,
    derivation_path: DerivationPathData,
    expected_address: &'static str,
    expected_public_key: &'static str,
    expected_private_key: &'static str,
    public_key_hash: &'static str,
    wallet_import_format: &'static str,
    hash: &'static str,
  }

  let test_vectors = vec![
    AddressTestVector {
      seed: "721c3401f1ffa1743b794812ab57109afd947acded2e39561192897fcc9226ae99a0de75ad313000190079438d3f8b5fa26c5036e1452e55e548ba629022bf82",
      derivation_path: DerivationPathData {
        purpose: Zeroizing::new(86),
        purpose_hardened: Zeroizing::new(true),
        coin: Zeroizing::new(0),
        coin_hardened: Zeroizing::new(true),
        account: Zeroizing::new(0),
        account_hardened: Zeroizing::new(true),
        change: Zeroizing::new(0),
        change_hardened: Zeroizing::new(false),
        address: Zeroizing::new(14),
        address_hardened: Zeroizing::new(false),
        last_index: Zeroizing::new(0),
      },
      coin_name: "Bitcoin",
      expected_address: "bc1pd43xsg2xwcgapwg04004aagpdtc0a4cws9cws8jwtwerav0awjgs57kqld",
      expected_public_key: "02260a06642d49a30d2c53c1f5b469e9a3b40189d6628cde9d49f4924ab432f56b",
      expected_private_key: "L1SW1Bx32eqATL9xDKjeki21Qo6BGaYajcs78jujy6ioGUcUBxbL",
      public_key_hash: "0x00",
      wallet_import_format: "0x80",
      hash: "sha256",
    },
    AddressTestVector {
      seed: "9c341cd0b1630abe1df1ce4c2cdc38c211b1afe37b93cc572846a068a01239dc1892dc9721a8fac7d5f893fab1a02060b96d9313644dc3f3e7616600215cb96c",
      derivation_path: DerivationPathData {
        purpose: Zeroizing::new(44),
        purpose_hardened: Zeroizing::new(true),
        coin: Zeroizing::new(0),
        coin_hardened: Zeroizing::new(true),
        account: Zeroizing::new(0),
        account_hardened: Zeroizing::new(true),
        change: Zeroizing::new(0),
        change_hardened: Zeroizing::new(false),
        address: Zeroizing::new(14),
        address_hardened: Zeroizing::new(false),
        last_index: Zeroizing::new(0),
      },
      coin_name: "Bitcoin",
      expected_address: "19PqdJXMssQNzRazrQVPDoKDwrfd8zyV9s",
      expected_public_key: "024cf9fc52a084abef7eea3e61df4b40f0ab2b5bffd9a832773fefe64456e3efa6",
      expected_private_key: "L3eQrW9T2gWtKksWorB7E6BouFvni1ngr34qoa6YwYqij7doanpU",
      public_key_hash: "0x00",
      wallet_import_format: "0x80",
      hash: "sha256",
    },
    AddressTestVector {
      seed: "9c341cd0b1630abe1df1ce4c2cdc38c211b1afe37b93cc572846a068a01239dc1892dc9721a8fac7d5f893fab1a02060b96d9313644dc3f3e7616600215cb96c",
      derivation_path: DerivationPathData {
        purpose: Zeroizing::new(44),
        purpose_hardened: Zeroizing::new(true),
        coin: Zeroizing::new(9),
        coin_hardened: Zeroizing::new(true),
        account: Zeroizing::new(0),
        account_hardened: Zeroizing::new(true),
        change: Zeroizing::new(0),
        change_hardened: Zeroizing::new(false),
        address: Zeroizing::new(0),
        address_hardened: Zeroizing::new(false),
        last_index: Zeroizing::new(0),
      },
      coin_name: "Counterparty",
      expected_address: "1JaMCowqDzuFzTGMBo3tELFudsbYTzFJV2",
      expected_public_key: "03fc1ec6f1fa293a971b136754319773988ca3f9113b1baddf421c73b9e5ecc62a",
      expected_private_key: "L3g2WxsDbS77bXAVkVaPtSosXiws4dCnhUqUEupMojWc8ysScSLw",
      public_key_hash: "0x00",
      wallet_import_format: "0x80",
      hash: "sha256",
    },
    AddressTestVector {
      seed: "9c341cd0b1630abe1df1ce4c2cdc38c211b1afe37b93cc572846a068a01239dc1892dc9721a8fac7d5f893fab1a02060b96d9313644dc3f3e7616600215cb96c",
      derivation_path: DerivationPathData {
        purpose: Zeroizing::new(44),
        purpose_hardened: Zeroizing::new(true),
        coin: Zeroizing::new(21),
        coin_hardened: Zeroizing::new(true),
        account: Zeroizing::new(0),
        account_hardened: Zeroizing::new(true),
        change: Zeroizing::new(0),
        change_hardened: Zeroizing::new(false),
        address: Zeroizing::new(0),
        address_hardened: Zeroizing::new(false),
        last_index: Zeroizing::new(0),
      },
      coin_name: "Open Assets",
      expected_address: "akGjhNYqVzC6s69y1kxkxckaUD4jKJr9KCk",
      expected_public_key: "02388f6a0a14b77466559dcd6c5d26fdc8b1b0a1ef5329846eaa4389cd7145c9f1",
      expected_private_key: "L5PwmZXVM7FipxabAFcujmLXumF6dYqsrRPfapG6ZGDK7hrU8bJw",
      public_key_hash: "0x00",
      wallet_import_format: "0x80",
      hash: "sha256",
    },
    AddressTestVector {
      seed: "514729a41c2c95ac0f828d9a359a0d72435fe75074ffe7a4fa0e1c157d16dd1604fde61f64a412b26012deba98bac6340a678c3c15983ee9cab8f93200b84a4c",
      derivation_path: DerivationPathData {
        purpose: Zeroizing::new(44),
        purpose_hardened: Zeroizing::new(true),
        coin: Zeroizing::new(60),
        coin_hardened: Zeroizing::new(true),
        account: Zeroizing::new(0),
        account_hardened: Zeroizing::new(true),
        change: Zeroizing::new(0),
        change_hardened: Zeroizing::new(false),
        address: Zeroizing::new(17),
        address_hardened: Zeroizing::new(false),
        last_index: Zeroizing::new(0),
      },
      coin_name: "Ethereum",
      expected_address: "0xb06483db0ba6003646a66a3e1cda52a07576aa86",
      expected_public_key: "0x0247e7ecda4c589b2ffd1caffbf0a3ce2a2aa06c3708b01cab8155d6a219fbfea6",
      expected_private_key: "0xf9e0e82c009606a8ae42f2b9fba9860463b7f6f62a7ea4f0172671e408c5ed4e",
      public_key_hash: "",
      wallet_import_format: "",
      hash: "keccak256",
    },
    AddressTestVector {
      seed: "514729a41c2c95ac0f828d9a359a0d72435fe75074ffe7a4fa0e1c157d16dd1604fde61f64a412b26012deba98bac6340a678c3c15983ee9cab8f93200b84a4c",
      derivation_path: DerivationPathData {
        purpose: Zeroizing::new(44),
        purpose_hardened: Zeroizing::new(true),
        coin: Zeroizing::new(5),
        coin_hardened: Zeroizing::new(true),
        account: Zeroizing::new(0),
        account_hardened: Zeroizing::new(true),
        change: Zeroizing::new(0),
        change_hardened: Zeroizing::new(false),
        address: Zeroizing::new(7),
        address_hardened: Zeroizing::new(false),
        last_index: Zeroizing::new(0),
      },
      coin_name: "Dash",
      expected_address: "XsESTZSEMo5EovfpiNMKbABrR7MCAtvqHu",
      expected_public_key: "032730387bb0a63e7734203a5770d2c1d9004e89e09cccec76079b8ccbbd4bebf5",
      expected_private_key: "XDMyRFdL8VcTMM5YxswdyHqKyoSWCrpFU5sabvLE9bmEq7gzoJ42",
      public_key_hash: "0x4c",
      wallet_import_format: "0xcc",
      hash: "sha256",
    },
    AddressTestVector {
      seed: "0be631a93733822132f3a961431dbde510ee2c0ba02a327f2ea550af544dea74d7fe3d2e4c633003cb3b4d4a7ad424ebc011e8a46f3ac9c74dd07fa98af914f2",
      derivation_path: DerivationPathData {
        purpose: Zeroizing::new(44),
        purpose_hardened: Zeroizing::new(true),
        coin: Zeroizing::new(3),
        coin_hardened: Zeroizing::new(true),
        account: Zeroizing::new(0),
        account_hardened: Zeroizing::new(true),
        change: Zeroizing::new(0),
        change_hardened: Zeroizing::new(false),
        address: Zeroizing::new(7),
        address_hardened: Zeroizing::new(true),
        last_index: Zeroizing::new(0),
      },
      coin_name: "Doge",
      expected_address: "DB6TUzw5zq9tu2ZRsPPxG13mQkmqTP8MUd",
      expected_public_key: "02455c276f60ecdb0aad688a8404d6ba6d67eb24bcd627b541d2581516bec65809",
      expected_private_key: "QVeeh6ojGZgeu3hoQDMGLRHDr7C9BsL3GMYWBFfYwY165sdDDWv5",
      public_key_hash: "0x1e",
      wallet_import_format: "0x9e",
      hash: "sha256",
    },
    AddressTestVector {
      seed: "2f4a25b911a40d0150a863ed813bde03fdcb4822d3bf0258eb681c4555b9bc7e4e2e1faac2522494cb180a9bafbf0dae4f7f732e33b817849546351fcaa5bf8f",
      derivation_path: DerivationPathData {
        purpose: Zeroizing::new(44),
        purpose_hardened: Zeroizing::new(true),
        coin: Zeroizing::new(118),
        coin_hardened: Zeroizing::new(true),
        account: Zeroizing::new(0),
        account_hardened: Zeroizing::new(true),
        change: Zeroizing::new(0),
        change_hardened: Zeroizing::new(false),
        address: Zeroizing::new(5),
        address_hardened: Zeroizing::new(true),
        last_index: Zeroizing::new(0),
      },
      coin_name: "Cosmos",
      expected_address: "cosmos1hxl4j3d6duxuz9f4dr26jhgflyjmusf59ucwwu",
      expected_public_key: "cosmospub1addwnpepq20ataq2l606gh7v3jtwwgp6taazgjjkunaus24dyg9whsyr4l3nswr7ynk",
      expected_private_key: "TkkQN6fYFHwBy5h0lz0HIpIxFWpWAxGgCFGqDWPHZ1A=",
      public_key_hash: "",
      wallet_import_format: "",
      hash: "sha256+ripemd160",
    },
    AddressTestVector {
      seed: "88a527d1eb006d48a2eaa729a33a631167bb90031069cf0a547de1656cb85227a5283041d863561079c4febfdfebe4f7f99a0cdb2199acf5a24cb7c65ec2e718",
      derivation_path: DerivationPathData {
        purpose: Zeroizing::new(44),
        purpose_hardened: Zeroizing::new(true),
        coin: Zeroizing::new(133),
        coin_hardened: Zeroizing::new(true),
        account: Zeroizing::new(436536547),
        account_hardened: Zeroizing::new(true),
        change: Zeroizing::new(1),
        change_hardened: Zeroizing::new(false),
        address: Zeroizing::new(234234350),
        address_hardened: Zeroizing::new(true),
        last_index: Zeroizing::new(0),
      },
      coin_name: "Zcash",
      expected_address: "t1RdfUot8Sc3rhLr4P6p7HL1ucAEyE2jFVW",
      expected_public_key: "022e17f55f9b93d3a695195c4ef86c5676285016597457ed6daa1edfea34ce6904",
      expected_private_key: "L4BSgzEtAwYt2VfFXfFxfiMkvrZhzoPpEAkPgiuJKyegwdY7ug5v",
      public_key_hash: "0x1CB8",
      wallet_import_format: "",
      hash: "sha256",
    },
    AddressTestVector {
      seed: "d556a6ce9fbee435e8286d4a63c55a2d65829c2d30da0cfb5acd7952d4a926af7fa7e29183ecef8ebf32185b01b7c17967037f3262bf002f009f6b56f0979b61",
      derivation_path: DerivationPathData {
        purpose: Zeroizing::new(44),
        purpose_hardened: Zeroizing::new(true),
        coin: Zeroizing::new(195),
        coin_hardened: Zeroizing::new(true),
        account: Zeroizing::new(0),
        account_hardened: Zeroizing::new(true),
        change: Zeroizing::new(0),
        change_hardened: Zeroizing::new(false),
        address: Zeroizing::new(12),
        address_hardened: Zeroizing::new(false),
        last_index: Zeroizing::new(0),
      },
      coin_name: "Tron",
      expected_address: "TWiUzvnaFKd7eceCTJcCkybpfGJoLy3jm2",
      expected_public_key: "03d793e73c60a171ea1734c90bfae77d234c274517a9c85df9242bab00e91bd685",
      expected_private_key: "e46e96c9713cc1e6a03fc345d60c009ff79ade19a144290c9b8cc517aa35e3ae",
      public_key_hash: "0x41",
      wallet_import_format: "",
      hash: "keccak256",
    },
    AddressTestVector {
      seed: "35c162ae06976248d83fbb82c9c898153a9627490a2d2ccc6230a6e6f43a41fb7326ddf6a244ea7c3c31ccff1a82dd8145744f32040833d3c99a088000ed70b5",
      derivation_path: DerivationPathData {
        purpose: Zeroizing::new(86),
        purpose_hardened: Zeroizing::new(true),
        coin: Zeroizing::new(2),
        coin_hardened: Zeroizing::new(true),
        account: Zeroizing::new(0),
        account_hardened: Zeroizing::new(true),
        change: Zeroizing::new(0),
        change_hardened: Zeroizing::new(false),
        address: Zeroizing::new(0),
        address_hardened: Zeroizing::new(false),
        last_index: Zeroizing::new(0),
      },
      coin_name: "Litecoin",
      expected_address: "ltc1ppfrf2gxdjhnqscxsl3mc6a5wppjavk3yrtxrt6uenw8pqyw9r2tsmq3wt0",
      expected_public_key: "03eada4d5ee9c7881106c24950e894c3861f2656f0964526be1196c68621d66c26",
      expected_private_key: "T6k3AKgtmo6DkpJnW2izoEsEXP5c6LDgwd9hj2UBHTqig7npNvXH",
      public_key_hash: "0x30",
      wallet_import_format: "0xb0",
      hash: "sha256",
    },
  ];

  for vector in test_vectors {
    let mut wallet = CryptoWallet::new();

    wallet.seed_secret.seed = Zeroizing::new(String::from(vector.seed));
    wallet.address_components.derivation_path = Zeroizing::new(vector.derivation_path.clone());
    wallet.address_components.coin_name = Zeroizing::new(vector.coin_name.to_string());
    wallet.address_components.public_key_hash = Zeroizing::new(vector.public_key_hash.to_string());
    wallet.address_components.key_derivation = Zeroizing::new(String::from("secp256k1"));
    wallet.address_components.wallet_import_format = Zeroizing::new(vector.wallet_import_format.to_string());
    wallet.address_components.hash = Zeroizing::new(vector.hash.to_string());
    wallet.wallet_data.bitcoin_legacy_addresses = *vector.derivation_path.purpose != 86;

    keys::generate_secp256k1_master_keys(&mut wallet).unwrap();
    keys::generate_secp256k1_child_keys(&mut wallet).unwrap();
    keys::generate_secp256k1_address(&mut wallet).unwrap();

    let addresses = wallet.addresses_by_coin.0.get(vector.coin_name).expect("Coin not found");
    let first = addresses.first().expect("No address stored for this coin");

    assert_eq!(first.address, Zeroizing::new(vector.expected_address.to_string()));
    assert_eq!(first.public_key, Zeroizing::new(vector.expected_public_key.to_string()));
    assert_eq!(first.private_key, Zeroizing::new(vector.expected_private_key.to_string()));
  }
}

#[test]
fn test_nano_address() {
  use super::*;

  // Official example from Nano docs
  let private_key = "781186FB9EF17DB6E3D1056550D9FAE5D5BBADA6A6BC370E4CBB938B1DC71DA3";
  let expected_public_key = "3068BB1CA04525BB0E416C485FE6A67FD52540227D267CC8B6E8DA958A7FA039";
  let expected_address = "nano_1e5aqegc1jb7qe964u4adzmcezyo6o146zb8hm6dft8tkp79za3sxwjym5rx";

  let mut priv_bytes = [0u8; 32];
  priv_bytes.copy_from_slice(&hex::decode(private_key).unwrap());
  let private_key: Zeroizing<[u8; 32]> = Zeroizing::new(priv_bytes);

  let pub_key: Zeroizing<[u8; 32]> = crate::keys::generate_nano_public_key(&private_key).unwrap();
  assert_eq!(hex::encode_upper(pub_key.as_ref()), expected_public_key);

  let address: Zeroizing<String> = crate::keys::generate_nano_address(&Zeroizing::new(pub_key.to_vec())).unwrap();
  assert_eq!(*address, expected_address);
}

#[test]
fn test_solana_address() {
  use super::*;

  struct SolanaTestVector {
    mnemonic_words: &'static str,
    derivation_path: DerivationPathData,
    expected_solana_address: &'static str,

    slip_derivation: bool,
  }

  let mut wallet = CryptoWallet::new();

  let test_vectors = vec![
    SolanaTestVector {
      mnemonic_words: "share skin first jacket drill suit gravity menu ticket sunset wise earn glass festival asthma system dial gossip balance mean unlock night cancel mandate",
      derivation_path: DerivationPathData {
        purpose: Zeroizing::new(44),
        purpose_hardened: Zeroizing::new(true),
        coin: Zeroizing::new(501),
        coin_hardened: Zeroizing::new(true),
        account: Zeroizing::new(0),
        account_hardened: Zeroizing::new(true),
        change: Zeroizing::new(0),
        change_hardened: Zeroizing::new(true),
        address: Zeroizing::new(0),
        address_hardened: Zeroizing::new(true),
        last_index: Zeroizing::new(0),
      },
      expected_solana_address: "GPAf4mYkMweFXpncRh5Fsc5vrzYEH8dEtW5Nv7BCW2cx",
      slip_derivation: false,
    },
    SolanaTestVector {
      mnemonic_words: "share skin first jacket drill suit gravity menu ticket sunset wise earn glass festival asthma system dial gossip balance mean unlock night cancel mandate",
      derivation_path: DerivationPathData {
        purpose: Zeroizing::new(44),
        purpose_hardened: Zeroizing::new(true),
        coin: Zeroizing::new(501),
        coin_hardened: Zeroizing::new(true),
        account: Zeroizing::new(7895),
        account_hardened: Zeroizing::new(true),
        change: Zeroizing::new(47158),
        change_hardened: Zeroizing::new(true),
        address: Zeroizing::new(0),
        address_hardened: Zeroizing::new(true),
        last_index: Zeroizing::new(0),
      },
      expected_solana_address: "6aprbLSWi1oHsT27ZSashtDaZBRXHmWoXP9trNzQWH8Y",
      slip_derivation: false,
    },
  ];

  for vector in test_vectors {
    wallet.wallet_data.slip_derivation_path = vector.slip_derivation;

    let seed_raw = _generate_seed_from_mnemonic(vector.mnemonic_words, None);

    let seed_hex = _convert_seed_to_hex(&seed_raw);

    wallet.seed_secret.seed = Zeroizing::new(seed_hex);

    let _ = keys::generate_ed25519_master_keys(&mut wallet);

    wallet.address_components.derivation_path = Zeroizing::new(vector.derivation_path.clone());

    match keys::generate_ed25519_child_keys(&mut wallet) {
      Ok(keys) => keys,
      Err(_) => {
        panic!("Can not generate child keys for ed25519");
      }
    };

    let address = bs58::encode(wallet.secret_keys.child_ed25519_keys.child_public_key_bytes.clone()).into_string();

    assert_eq!(address, vector.expected_solana_address);
  }
}

#[test]
fn test_nem_address() {
  use super::*;

  struct NemTestVector {
    mnemonic_words: &'static str,
    derivation_path: DerivationPathData,
    expected_nem_address: &'static str,
    public_key_hash: &'static str,

    slip_derivation: bool,
  }

  let mut wallet = CryptoWallet::new();

  let test_vectors = vec![
    NemTestVector {
      mnemonic_words: "dose dumb cluster card tag swallow despair helmet garden pave dust gas",
      derivation_path: DerivationPathData {
        purpose: Zeroizing::new(44),
        purpose_hardened: Zeroizing::new(true),
        coin: Zeroizing::new(43),
        coin_hardened: Zeroizing::new(true),
        account: Zeroizing::new(0),
        account_hardened: Zeroizing::new(true),
        change: Zeroizing::new(0),
        change_hardened: Zeroizing::new(true),
        address: Zeroizing::new(0),
        address_hardened: Zeroizing::new(true),
        last_index: Zeroizing::new(0),
      },
      expected_nem_address: "NAUIMD-KYQL63-AMH3XL-LYB55M-VDBRWT-ZOYV3E-GZGQ",
      public_key_hash: "0x68",
      slip_derivation: false,
    },
    NemTestVector {
      mnemonic_words: "dose dumb cluster card tag swallow despair helmet garden pave dust gas",
      derivation_path: DerivationPathData {
        purpose: Zeroizing::new(44),
        purpose_hardened: Zeroizing::new(true),
        coin: Zeroizing::new(43),
        coin_hardened: Zeroizing::new(true),
        account: Zeroizing::new(0),
        account_hardened: Zeroizing::new(true),
        change: Zeroizing::new(0),
        change_hardened: Zeroizing::new(true),
        address: Zeroizing::new(1),
        address_hardened: Zeroizing::new(true),
        last_index: Zeroizing::new(0),
      },
      expected_nem_address: "NCKOWW-MEZUSS-AUF2R4-7SHIFM-ZUKGHK-74QC2P-SUI3",
      public_key_hash: "0x68",
      slip_derivation: false,
    },
  ];

  for vector in test_vectors {
    wallet.wallet_data.slip_derivation_path = vector.slip_derivation;

    let seed_raw = _generate_seed_from_mnemonic(vector.mnemonic_words, None);

    let seed_hex = _convert_seed_to_hex(&seed_raw);

    wallet.seed_secret.seed = Zeroizing::new(seed_hex);

    let _ = keys::generate_ed25519_master_keys(&mut wallet);

    wallet.address_components.derivation_path = Zeroizing::new(vector.derivation_path.clone());

    match keys::generate_ed25519_child_keys(&mut wallet) {
      Ok(keys) => keys,
      Err(_) => {
        panic!("Can not generate child keys for ed25519");
      }
    };

    let pub_key_hash: Zeroizing<String> = Zeroizing::new(vector.public_key_hash.to_string());
    let pubkey_array: Zeroizing<[u8; 32]> = Zeroizing::new(
      wallet
        .secret_keys
        .child_ed25519_keys
        .child_public_key_bytes
        .as_slice()
        .try_into()
        .unwrap(),
    );
    let address = keys::generate_nem_address(pubkey_array, pub_key_hash).unwrap().to_string();

    assert_eq!(address, vector.expected_nem_address);
  }
}

#[test]
fn test_cardano_address() {
  use super::*;
  use crate::{CryptoWallet, Zeroizing, keys};

  struct CardanoTestVector {
    entropy: &'static str,
    mnemonic_words: &'static str,
    derivation_path: DerivationPathData,
    expected_cardano_address: &'static str,
  }

  let test_vectors = [
    CardanoTestVector {
      entropy: "0010110110001100111001010001111001100001011010010111111011011101010111010010000000100010010110001101101001110001111010100110111110110011001111111001110110110100110000110111100001010001110100000001000110010111001100111011111110010000111101111100101101100011",
      mnemonic_words: "collect grunt elegant security obey huge innocent affair flee squeeze kind term crop solution spread humor fade letter grape guess weekend know collect hire",
      derivation_path: DerivationPathData {
        purpose: Zeroizing::new(1852),
        purpose_hardened: Zeroizing::new(true),
        coin: Zeroizing::new(1815),
        coin_hardened: Zeroizing::new(true),
        account: Zeroizing::new(0),
        account_hardened: Zeroizing::new(true),
        change: Zeroizing::new(0),
        change_hardened: Zeroizing::new(false),
        address: Zeroizing::new(0),
        address_hardened: Zeroizing::new(false),
        last_index: Zeroizing::new(0),
      },
      expected_cardano_address: "addr1q9rp04hse3884rrg0nsx9cx45vmwv97er8c29fdjf59al22ecq0jq2lgzysw9e7wxx7vjkzqx50nfscr849p3g5hddxqv7s5cd",
    },
    CardanoTestVector {
      entropy: "0010010100010010111101011010111100101000100100011010101000001001101011101100011101101101010010101010101110111100011001011001111111010100001100111010010000111000",
      mnemonic_words: "celery nut hint eye boy age roast unit enjoy fuel bonus distance drip spirit token",
      derivation_path: DerivationPathData {
        purpose: Zeroizing::new(1852),
        purpose_hardened: Zeroizing::new(true),
        coin: Zeroizing::new(1815),
        coin_hardened: Zeroizing::new(true),
        account: Zeroizing::new(0),
        account_hardened: Zeroizing::new(true),
        change: Zeroizing::new(0),
        change_hardened: Zeroizing::new(false),
        address: Zeroizing::new(14),
        address_hardened: Zeroizing::new(false),
        last_index: Zeroizing::new(0),
      },
      expected_cardano_address: "addr1qxffzk0vj5qrvmg7yhydxtgm3y26j6cz2c4u452ck5zvp7ksy4syvf4wuwfafl2u6xcsnt28ylyn4wudm45ye7n8kj3q5zskds",
    },
  ];

  for (vector_idx, vector) in test_vectors.iter().enumerate() {
    let mut wallet = CryptoWallet::new();
    wallet.seed_secret.raw_entropy = Zeroizing::new(vector.entropy.to_string());
    wallet.wallet_data.hardened_address = *vector.derivation_path.address_hardened;

    let seed_raw = _generate_seed_from_mnemonic(vector.mnemonic_words, None);
    let seed_hex = _convert_seed_to_hex(&seed_raw);

    wallet.seed_secret.seed = Zeroizing::new(seed_hex);
    wallet.address_components.derivation_path = Zeroizing::new(vector.derivation_path.clone());

    let address =
      keys::derive_cardano_address_from_seed_bytes(&mut wallet).unwrap_or_else(|err| panic!("Test vector #{} failed: {}", vector_idx + 1, err));

    assert_eq!(address, vector.expected_cardano_address, "Test vector #{} failed", vector_idx + 1);
  }
}

//                          Wallet save & open function
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

#[test]
fn check_wallet_save_open_function() {
  use super::*;
  use crate::{CryptoWallet, Zeroizing, keys};
  use std::cell::RefCell;
  use std::rc::Rc;

  let wallet_name = "Test";
  let wallet_file = format!("{}-1.svg", wallet_name);

  let mut new_wallet: CryptoWallet = CryptoWallet::new();
  let mut save_wallet: crypt::SaveWalletDialog = crypt::SaveWalletDialog::new();
  let mut open_wallet = crypt::OpenWalletDialog::new();

  new_wallet.wallet_gen_state = WalletGenState::ReadyToGenerate;

  let _ = keys::generate_seed(&mut new_wallet, Zeroizing::new(String::from("RNG")));
  let _ = keys::generate_secp256k1_master_keys(&mut new_wallet);
  let _ = keys::generate_secp256k1_child_keys(&mut new_wallet);
  let _ = keys::generate_ed25519_master_keys(&mut new_wallet);
  let _ = keys::generate_ed25519_child_keys(&mut new_wallet);
  let _ = keys::generate_addresses_for_all_coins(&mut new_wallet);

  let wrapped: Rc<RefCell<Zeroizing<CryptoWallet>>> = Rc::new(RefCell::new(Zeroizing::new(new_wallet.clone())));

  save_wallet.wallet_to_save = Some(wrapped);
  save_wallet.password = String::from(wallet_name);
  save_wallet.wallet_name = String::from(wallet_name);
  save_wallet.direct_save = true;
  save_wallet.save_location = None;

  let _ = crypt::SaveWalletDialog::save_wallet(&mut save_wallet);

  open_wallet.selected_svgs = [wallet_file.clone()].to_vec();
  let decoded_svg = crypt::load_svg(&wallet_file).unwrap();

  let data: Zeroizing<Vec<u8>> = crypt::decrypt_wallet(Zeroizing::new(String::from("Test")), &decoded_svg).unwrap();

  let payload: crypt::WalletPayload = crypt::parse_payload(data).unwrap();

  assert_eq!(payload.seed_secret.full_entropy, new_wallet.seed_secret.full_entropy.clone());

  assert_eq!(
    payload.seed_secret.mnemonic_passphrase,
    new_wallet.seed_secret.mnemonic_passphrase.clone()
  );

  assert_eq!(
    payload.seed_secret.mnemonic_passphrase,
    new_wallet.seed_secret.mnemonic_passphrase.clone()
  );

  // TODO: Add more checks, at least address and private key!

  let _ = std::fs::remove_file(wallet_file);
}

//                                 Other test
// -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

// TODO: Recreate Monero testing vectors
//   #[test]
//   fn test_monero_derivation_slip0010() {
//     let mut wallet = CryptoWallet::new();
//
// struct _MoneroTestVector {
//   bip39_mnemonic_words: &'static str,
//   bip39_mnemonic_passphrase: &'static str,
//
//   _expected_slip0010_monero_words: &'static str,
//   expected_monero_address: &'static str,
//
//   expected_monero_spend_priv: &'static str,
//   expected_monero_view_priv: &'static str,
//
//   expected_monero_spend_pub: &'static str,
//   expected_monero_view_pub: &'static str,
// }
//
//
//     let test_vectors = vec![
//       // Sources:
//       // https://coinomi.github.io/tools/bip39/
//       // https://monero-web.com/verify
//       _MoneroTestVector {
//         bip39_mnemonic_words: "permit universe parent weapon amused modify essay borrow tobacco budget walnut lunch consider gallery ride amazing frog forget treat market chapter velvet useless topple",
//         bip39_mnemonic_passphrase: "a",
//
//         _expected_slip0010_monero_words: "maul loudly nearby buffet hacksaw zones kernels edgy baffles match extra eclipse uphill arena hounded wobbly actress muppet pebbles onward rift tether scrub snake rift",
//         expected_monero_address: "4BBKEeg8iH3JtyQKfdh5KRYNe2WK4aDMBeMwPvkjrm45BQ8bVHurmLyadDx3EiM6AjNH7JJx5TMNrjC4JLZEhszc5f3G8Yg",
//
//         expected_monero_spend_priv: "0b86cf0e71204ca3cdc389daf0bb1cf654ac7d54edfed68a9faf921ba140a708",
//         expected_monero_view_priv: "3b1213f644062fbfb15c4fa35e656659e4105ac728b791ce5ad10af98bc6d200",
//
//         expected_monero_spend_pub: "fc25f0a1a1fb4e6afe5ffa15cd06fcbb913eb55605d09adf5de735163d4f4a3e",
//         expected_monero_view_pub: "2ba093948b429ec90729ecd0f705b87f36154612756433fc3dc7d8dbbf646529",
//       },
//       //       _MoneroTestVector {
//       //         bip39_mnemonic_words: "wave spawn demand people ticket garage achieve dance visa easily rather genuine income brush sound soon ask sail depth planet monster average timber space",
//       //         bip39_mnemonic_passphrase: "",
//       //
//       //         expected_monero_words: "pistons apex avidly dexterity hounded tusks pyramid hamburger bomb semifinal iceberg ungainly bugs afloat inbound fountain sphere blip pager rash oars later space suitcase pistons",
//       //         expected_monero_address: "45WJGeDNjrHQo9Yqs79ZxAGRfDwaWZh2nc8pDd2WhGs7RYZkcUMRD88dWm6Dj3SKuRSUnzPngC2afENuUcMss5rURgGjXZv",
//       //
//       //         expected_monero_spend_priv: "78905d063d74f17d619c9fc1c34ff57e62000d64f24d584f7f5dabe4710fad03",
//       //         expected_monero_view_priv: "569ed35391369004246a79596cfab1ed4fdc48fd9e164957bf68da2ece6c8a05",
//       //
//       //         expected_monero_spend_pub: "66747bfee0367a8e43ce2dd4648b5f5c3892187138d8f7d20e8a811c86672692",
//       //         expected_monero_view_pub: "bd840eb326646dda4c2f8629513a309854825b214f0e0c4ffad7a2473a5975da",
//       //       },
//     ];
//
//     for vector in test_vectors {
//       wallet.seed_secret.mnemonic_words = Zeroizing::new(vector.bip39_mnemonic_words.to_string());
//       wallet.seed_secret.mnemonic_passphrase = Zeroizing::new(vector.bip39_mnemonic_passphrase.to_string());
//
//       wallet.wallet_data.slip_derivation_path = true;
//
//       let seed_raw = match _generate_seed_from_mnemonic(vector.bip39_mnemonic_words, Some(vector.bip39_mnemonic_passphrase)) {
//         Ok(seed) => seed,
//         Err(_) => {
//           panic!("Can not generate seed from mnemonic");
//         }
//       };
//
//       let spend_priv = monero_slip0010_spend_key(bip39_seed);
//       let view_priv = Scalar::from_bytes_mod_order(cn_fast_hash(&spend_priv)).to_bytes();
//
//       let spend_pub = monero_pubkey(&spend_priv);
//       let view_pub = monero_pubkey(&view_priv);
//
//       let address = generate_monero_address(&spend_pub, &view_pub);
//
//       (address, spend_priv, view_priv, spend_pub, view_pub)
//
//       assert_eq!(address, vector.expected_monero_address);
//
//       assert_eq!(hex::encode(spend_priv), vector.expected_monero_spend_priv);
//
//       assert_eq!(hex::encode(view_priv), vector.expected_monero_view_priv);
//
//       assert_eq!(hex::encode(spend_pub), vector.expected_monero_spend_pub);
//
//       assert_eq!(hex::encode(view_pub), vector.expected_monero_view_pub);
//     }
//   }

#[test]
fn test_sr25519_coins() {
  use super::*;
  use crate::{CryptoWallet, Zeroizing, keys};

  struct TestVectors {
    mnemonic_words: &'static str,
    derivation_path: DerivationPathData,
    expected_address: &'static str,
    wif: &'static str,
  }

  let test_vectors = [
    TestVectors {
      mnemonic_words: "cement identify ship alley frozen bag top truth blame tunnel farm inflict owner olive kiss will thumb monkey trip around base expire come damage",
      derivation_path: DerivationPathData {
        purpose: Zeroizing::new(44),
        purpose_hardened: Zeroizing::new(true),
        coin: Zeroizing::new(354),
        coin_hardened: Zeroizing::new(true),
        account: Zeroizing::new(0),
        account_hardened: Zeroizing::new(true),
        change: Zeroizing::new(0),
        change_hardened: Zeroizing::new(true),
        address: Zeroizing::new(0),
        address_hardened: Zeroizing::new(true),
        last_index: Zeroizing::new(0),
      },
      expected_address: "1h43RjFcar9q5JBx5BAGMwLCwP1rd5RoDjubCtPmH5QGwbo",
      wif: "0",
    },
    TestVectors {
      mnemonic_words: "patient frequent bean race client cruise avoid second security flight catalog hope",
      derivation_path: DerivationPathData {
        purpose: Zeroizing::new(44),
        purpose_hardened: Zeroizing::new(true),
        coin: Zeroizing::new(434),
        coin_hardened: Zeroizing::new(true),
        account: Zeroizing::new(0),
        account_hardened: Zeroizing::new(true),
        change: Zeroizing::new(0),
        change_hardened: Zeroizing::new(true),
        address: Zeroizing::new(1),
        address_hardened: Zeroizing::new(true),
        last_index: Zeroizing::new(0),
      },
      expected_address: "CbVXNMfjADbk3hZ68rH7SRjRScamnpC9bBciSa1Bk2U7kC6",
      wif: "2",
    },
  ];

  for (vector_idx, vector) in test_vectors.iter().enumerate() {
    let mut wallet = CryptoWallet::new();

    wallet.seed_secret.mnemonic_words = Zeroizing::new(vector.mnemonic_words.to_string());
    wallet.address_components.derivation_path = Zeroizing::new(vector.derivation_path.clone());
    // wallet.wallet_data.slip_derivation_path = true;
    wallet.address_components.wallet_import_format = Zeroizing::new(vector.wif.to_string());

    let _ = keys::generate_sr25519_master_keys(&mut wallet);
    let _ = keys::generate_sr25519_child_keys(&mut wallet);

    let address = keys::generate_sr25519_address(&mut wallet).unwrap();

    assert_eq!(*address, vector.expected_address, "Test vector #{} failed", vector_idx + 1);
  }
}
