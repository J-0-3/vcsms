import random
import os
import sys
sys.path.append("..")
from testing import Test, TestSet
sys.path.append("../..")
import vcsms.cryptography.aes256 as aes256
from vcsms.cryptography.exceptions import DecryptionFailureException

if __name__ == "__main__":
    print("Generating unit tests...")

one_byte_test_vectors = []
for i in range(256):
    key = random.randrange(0, 2**256)
    iv = random.randrange(0, 2**128)
    ciphertext = aes256.encrypt_cbc(i.to_bytes(1, 'big'), key, iv)
    one_byte_test_vectors.append(((ciphertext, key, iv), i.to_bytes(1, 'big')))

unsuccessful_decryption_1_byte_test = Test(
    "failure to encrypt and decrypt 1B with wrong key",
    aes256.decrypt_cbc,
    [
        ((ciphertext, random.randrange(0, 2**256), iv), None) 
        for (ciphertext, _, iv), _ in one_byte_test_vectors
    ],
    "raises",
    DecryptionFailureException
)

successful_decryption_1_byte_test = Test(
    "encryption and decryption of every 1B value",
    aes256.decrypt_cbc,
    one_byte_test_vectors,
    "eq"
)

thirty_two_byte_test_vectors = []
for i in range(500):
    key = random.randrange(0, 2**256)
    iv = random.randrange(0, 2**128)
    plaintext = random.randbytes(32)
    ciphertext = aes256.encrypt_cbc(plaintext, key, iv)
    thirty_two_byte_test_vectors.append(((ciphertext, key, iv), plaintext))

successful_decryption_32_byte_test = Test(
    "500 encryptions and decryptions of 32B",
    aes256.decrypt_cbc,
    thirty_two_byte_test_vectors,
    "eq"
)

unsuccessful_decryption_32_byte_test = Test(
    "500 failures to encrypt and decrypt 32B with wrong key",
    aes256.decrypt_cbc,
    [
        ((ciphertext, random.randrange(0, 2**256), iv), None)
        for (ciphertext, _, iv), _ in thirty_two_byte_test_vectors
    ],
    "raises",
    DecryptionFailureException
)

zero_key_encryption_test = Test(
    "100 1KB values encrypted and decrypted with key 0",
    aes256.decrypt_cbc,
    [
        ((aes256.encrypt_cbc(plaintext, 0, 0), 0, 0), plaintext) 
        for plaintext in [random.randbytes(1024) for i in range(100)]
    ],
    "eq"
)

zero_key_decryption_failure_test = Test(
    "500 failures to decrypt 1KB encrypted with key 0 using wrong key",
    aes256.decrypt_cbc,
    [
        ((ciphertext, random.randrange(0, 2**256), random.randrange(0, 2**128)), None) 
        for (ciphertext, _, _), _ in zero_key_encryption_test.tests
    ],
    "raises",
    DecryptionFailureException
)

nist_aesavs_GFSbox_test = Test(
    "NIST AES Algorithm Verification Suite 'GFSBox'",
    lambda p: aes256.encrypt_cbc(p, 0, 0, True).hex()[:32],  # NIST vectors do not use PKCS#7, remove the added block
    [
        ((bytes.fromhex('014730f80ac625fe84f026c60bfd547d'),), '5c9d844ed46f9885085e5d6a4f94c7d7'),
        ((bytes.fromhex('0b24af36193ce4665f2825d7b4749c98'),), 'a9ff75bd7cf6613d3731c77c3b6d0c04'),
        ((bytes.fromhex('761c1fe41a18acf20d241650611d90f1'),), '623a52fcea5d443e48d9181ab32c7421'),
        ((bytes.fromhex('8a560769d605868ad80d819bdba03771'),), '38f2c7ae10612415d27ca190d27da8b4'),
        ((bytes.fromhex('91fbef2d15a97816060bee1feaa49afe'),), '1bc704f1bce135ceb810341b216d7abe')
    ],
    "eq"
)

nist_aesavs_KeySBox_test = Test(
    "NIST AES Algorithm Verification Suite 'KeySBox'",
    lambda k: aes256.encrypt_cbc(b'\x00' * 16, k, 0, True).hex()[:32],
    [
        ((0xc47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558,), '46f2fb342d6f0ab477476fc501242c5f'),
        ((0x28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64,), '4bf3b0a69aeb6657794f2901b1440ad4'),
        ((0xc1cc358b449909a19436cfbb3f852ef8bcb5ed12ac7058325f56e6099aab1a1c,), '352065272169abf9856843927d0674fd'),
        ((0x984ca75f4ee8d706f46c2d98c0bf4a45f5b00d791c2dfeb191b5ed8e420fd627,), '4307456a9e67813b452e15fa8fffe398'),
        ((0xb43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f,), '4663446607354989477a5c6f0f007ef4'),
        ((0x1d85a181b54cde51f0e098095b2962fdc93b51fe9b88602b3f54130bf76a5bd9,), '531c2c38344578b84d50b3c917bbb6e1'),
        ((0xdc0eba1f2232a7879ded34ed8428eeb8769b056bbaf8ad77cb65c3541430b4cf,), 'fc6aec906323480005c58e7e1ab004ad'),
        ((0xf8be9ba615c5a952cabbca24f68f8593039624d524c816acda2c9183bd917cb9,), 'a3944b95ca0b52043584ef02151926a8'),
        ((0x797f8b3d176dac5b7e34a2d539c4ef367a16f8635f6264737591c5c07bf57a3e,), 'a74289fe73a4c123ca189ea1e1b49ad5'),
        ((0x6838d40caf927749c13f0329d331f448e202c73ef52c5f73a37ca635d4c47707,), 'b91d4ea4488644b56cf0812fa7fcf5fc'),
        ((0xccd1bc3c659cd3c59bc437484e3c5c724441da8d6e90ce556cd57d0752663bbc,), '304f81ab61a80c2e743b94d5002a126b'),
        ((0x13428b5e4c005e0636dd338405d173ab135dec2a25c22c5df0722d69dcc43887,), '649a71545378c783e368c9ade7114f6c'),
        ((0x07eb03a08d291d1b07408bf3512ab40c91097ac77461aad4bb859647f74f00ee,), '47cb030da2ab051dfc6c4bf6910d12bb'),
        ((0x90143ae20cd78c5d8ebdd6cb9dc1762427a96c78c639bccc41a61424564eafe1,), '798c7c005dee432b2c8ea5dfa381ecc3'),
        ((0xb7a5794d52737475d53d5a377200849be0260a67a2b22ced8bbef12882270d07,), '637c31dc2591a07636f646b72daabbe7'),
        ((0xfca02f3d5011cfc5c1e23165d413a049d4526a991827424d896fe3435e0bf68e,), '179a49c712154bbffbe6e7a84a18e220')
    ],
    "eq"
)

vartxt_plaintexts = []
for i in range(32):
    for c in ('8', 'c', 'e', 'f'):
        vartxt_plaintexts.append(bytes.fromhex('f' * i + c + '0' * (31 - i)))

with open(os.path.join(os.path.dirname(__file__), 'vartxt'), 'r') as f:
    vartxt_ciphertexts = f.read().split('\n')

nist_aesavs_VarTxt_test = Test(
    "NIST AES Algorithm Verification Suite 'VarTxt'",
    lambda p: aes256.encrypt_cbc(p, 0, 0, True).hex(),
    list(zip([(x,) for x in vartxt_plaintexts], vartxt_ciphertexts)),
    "eq"
)

varkey_keys = []
for i in range(64):
    for c in ('8', 'c', 'e', 'f'):
        varkey_keys.append(int('f' * i + c + '0' * (63 - i), 16))

with open(os.path.join(os.path.dirname(__file__), 'varkey'), 'r') as f:
    vartxt_ciphertexts = f.read().split('\n')

nist_aesavs_VarKey_test = Test(
    "NIST AES Algorithm Verification Suite 'VarKey'",
    lambda k: aes256.encrypt_cbc(b'\x00' * 16, k, 0, True).hex(),
    list(zip([(x, ) for x in varkey_keys], vartxt_ciphertexts)),
    "eq"
)

nist_aesavs_multiblock_message_test_enc = Test(
    "NIST AES Algorithm Verification Suite Multiblock Message Encrypt",
    lambda k, i, p: aes256.encrypt_cbc(p, k, i, True).hex(),
    [
        ((0x6ed76d2d97c69fd1339589523931f2a6cff554b15f738f21ec72dd97a7330907, 0x851e8764776e6796aab722dbb644ace8, bytes.fromhex('6282b8c05c5c1530b97d4816ca434762')), '6acc04142e100a65f51b97adf5172c41'),
        ((0xdce26c6b4cfb286510da4eecd2cffe6cdf430f33db9b5f77b460679bd49d13ae, 0xfdeaa134c8d7379d457175fd1a57d3fc, bytes.fromhex('50e9eee1ac528009e8cbcd356975881f957254b13f91d7c6662d10312052eb00')), '2fa0df722a9fd3b64cb18fb2b3db55ff2267422757289413f8f657507412a64c'),
        ((0xfe8901fecd3ccd2ec5fdc7c7a0b50519c245b42d611a5ef9e90268d59f3edf33, 0xbd416cb3b9892228d8f1df575692e4d0, bytes.fromhex('8d3aa196ec3d7c9b5bb122e7fe77fb1295a6da75abe5d3a510194d3a8a4157d5c89d40619716619859da3ec9b247ced9')), '608e82c7ab04007adb22e389a44797fed7de090c8c03ca8a2c5acd9e84df37fbc58ce8edb293e98f02b640d6d1d72464'),
        ((0x0493ff637108af6a5b8e90ac1fdf035a3d4bafd1afb573be7ade9e8682e663e5, 0xc0cd2bebccbb6c49920bd5482ac756e8, bytes.fromhex('8b37f9148df4bb25956be6310c73c8dc58ea9714ff49b643107b34c9bff096a94fedd6823526abc27a8e0b16616eee254ab4567dd68e8ccd4c38ac563b13639c')), '05d5c77729421b08b737e41119fa4438d1f570cc772a4d6c3df7ffeda0384ef84288ce37fc4c4c7d1125a499b051364c389fd639bdda647daa3bdadab2eb5594'),
        ((0x9adc8fbd506e032af7fa20cf5343719de6d1288c158c63d6878aaf64ce26ca85, 0x11958dc6ab81e1c7f01631e9944e620f, bytes.fromhex('c7917f84f747cd8c4b4fedc2219bdbc5f4d07588389d8248854cf2c2f89667a2d7bcf53e73d32684535f42318e24cd45793950b3825e5d5c5c8fcd3e5dda4ce9246d18337ef3052d8b21c5561c8b660e')), '9c99e68236bb2e929db1089c7750f1b356d39ab9d0c40c3e2f05108ae9d0c30b04832ccdbdc08ebfa426b7f5efde986ed05784ce368193bb3699bc691065ac62e258b9aa4cc557e2b45b49ce05511e65'),
        ((0x73b8faf00b3302ac99855cf6f9e9e48518690a5906a4869d4dcf48d282faae2a, 0xb3cb97a80a539912b8c21f450d3b9395, bytes.fromhex('3adea6e06e42c4f041021491f2775ef6378cb08824165edc4f6448e232175b60d0345b9f9c78df6596ec9d22b7b9e76e8f3c76b32d5d67273f1d83fe7a6fc3dd3c49139170fa5701b3beac61b490f0a9e13f844640c4500f9ad3087adfb0ae10')), 'ac3d6dbafe2e0f740632fd9e820bf6044cd5b1551cbb9cc03c0b25c39ccb7f33b83aacfca40a3265f2bbff879153448acacb88fcfb3bb7b10fe463a68c0109f028382e3e557b1adf02ed648ab6bb895df0205d26ebbfa9a5fd8cebd8e4bee3dc'),
        ((0x9ddf3745896504ff360a51a3eb49c01b79fccebc71c3abcb94a949408b05b2c9, 0xe79026639d4aa230b5ccffb0b29d79bc, bytes.fromhex('cf52e5c3954c51b94c9e38acb8c9a7c76aebdaa9943eae0a1ce155a2efdb4d46985d935511471452d9ee64d2461cb2991d59fc0060697f9a671672163230f367fed1422316e52d29eceacb8768f56d9b80f6d278093c9a8acd3cfd7edd8ebd5c293859f64d2f8486ae1bd593c65bc014')), '34df561bd2cfebbcb7af3b4b8d21ca5258312e7e2e4e538e35ad2490b6112f0d7f148f6aa8d522a7f3c61d785bd667db0e1dc4606c318ea4f26af4fe7d11d4dcff0456511b4aed1a0d91ba4a1fd6cd9029187bc5881a5a07fe02049d39368e83139b12825bae2c7be81e6f12c61bb5c5'),
        ((0x458b67bf212d20f3a57fce392065582dcefbf381aa22949f8338ab9052260e1d, 0x4c12effc5963d40459602675153e9649, bytes.fromhex('256fd73ce35ae3ea9c25dd2a9454493e96d8633fe633b56176dce8785ce5dbbb84dbf2c8a2eeb1e96b51899605e4f13bbc11b93bf6f39b3469be14858b5b720d4a522d36feed7a329c9b1e852c9280c47db8039c17c4921571a07d1864128330e09c308ddea1694e95c84500f1a61e614197e86a30ecc28df64ccb3ccf5437aa')), '90b7b9630a2378f53f501ab7beff039155008071bc8438e789932cfd3eb1299195465e6633849463fdb44375278e2fdb1310821e6492cf80ff15cb772509fb426f3aeee27bd4938882fd2ae6b5bd9d91fa4a43b17bb439ebbe59c042310163a82a5fe5388796eee35a181a1271f00be29b852d8fa759bad01ff4678f010594cd'),
        ((0xd2412db0845d84e5732b8bbd642957473b81fb99ca8bff70e7920d16c1dbec89, 0x51c619fcf0b23f0c7925f400a6cacb6d, bytes.fromhex('026006c4a71a180c9929824d9d095b8faaa86fc4fa25ecac61d85ff6de92dfa8702688c02a282c1b8af4449707f22d75e91991015db22374c95f8f195d5bb0afeb03040ff8965e0e1339dba5653e174f8aa5a1b39fe3ac839ce307a4e44b4f8f1b0063f738ec18acdbff2ebfe07383e734558723e741f0a1836dafdf9de82210a9248bc113b3c1bc8b4e252ca01bd803')), '0254b23463bcabec5a395eb74c8fb0eb137a07bc6f5e9f61ec0b057de305714f8fa294221c91a159c315939b81e300ee902192ec5f15254428d8772f79324ec43298ca21c00b370273ee5e5ed90e43efa1e05a5d171209fe34f9f29237dba2a6726650fd3b1321747d1208863c6c3c6b3e2d879ab5f25782f08ba8f2abbe63e0bedb4a227e81afb36bb6645508356d34'),
        ((0x48be597e632c16772324c8d3fa1d9c5a9ecd010f14ec5d110d3bfec376c5532b, 0xd6d581b8cf04ebd3b6eaa1b53f047ee1, bytes.fromhex('0c63d413d3864570e70bb6618bf8a4b9585586688c32bba0a5ecc1362fada74ada32c52acfd1aa7444ba567b4e7daaecf7cc1cb29182af164ae5232b002868695635599807a9a7f07a1f137e97b1e1c9dabc89b6a5e4afa9db5855edaa575056a8f4f8242216242bb0c256310d9d329826ac353d715fa39f80cec144d6424558f9f70b98c920096e0f2c855d594885a00625880e9dfb734163cecef72cf030b8')), 'fc5873e50de8faf4c6b84ba707b0854e9db9ab2e9f7d707fbba338c6843a18fc6facebaf663d26296fb329b4d26f18494c79e09e779647f9bafa87489630d79f4301610c2300c19dbf3148b7cac8c4f4944102754f332e92b6f7c5e75bc6179eb877a078d4719009021744c14f13fd2a55a2b9c44d18000685a845a4f632c7c56a77306efa66a24d05d088dcd7c13fe24fc447275965db9e4d37fbc9304448cd')
    ],
    "eq"
)

nist_aesavs_multiblock_message_test_dec = Test(
    "NIST AES Algorithm Verification Suite Multiblock Message Decrypt",
    lambda k, i, c: aes256.decrypt_cbc(c, k, i, True).hex(),
    [
        ((0x43e953b2aea08a3ad52d182f58c72b9c60fbe4a9ca46a3cb89e3863845e22c9e, 0xddbbb0173f1e2deb2394a62aa2a0240e, bytes.fromhex('d51d19ded5ca4ae14b2b20b027ffb020')), '07270d0e63aa36daed8c6ade13ac1af1'),
        ((0xaddf88c1ab997eb58c0455288c3a4fa320ada8c18a69cc90aa99c73b174dfde6, 0x60cc50e0887532e0d4f3d2f20c3c5d58, bytes.fromhex('6cb4e2f4ddf79a8e08c96c7f4040e8a83266c07fc88dd0074ee25b00d445985a')), '98a8a9d84356bf403a9ccc384a06fe043dfeecb89e59ce0cb8bd0a495ef76cf0'),
        ((0x54682728db5035eb04b79645c64a95606abb6ba392b6633d79173c027c5acf77, 0x2eb94297772851963dd39a1eb95d438f, bytes.fromhex('e4046d05385ab789c6a72866e08350f93f583e2a005ca0faecc32b5cfc323d461c76c107307654db5566a5bd693e227c')), '0faa5d01b9afad3bb519575daaf4c60a5ed4ca2ba20c625bc4f08799addcf89d19796d1eff0bd790c622dc22c1094ec7'),
        ((0x7482c47004aef406115ca5fd499788d582efc0b29dc9e951b1f959406693a54f, 0x485ebf2215d20b816ea53944829717ce, bytes.fromhex('6c24f19b9c0b18d7126bf68090cb8ae72db3ca7eabb594f506aae7a2493e5326a5afae4ec4d109375b56e2b6ff4c9cf639e72c63dc8114c796df95b3c6b62021')), '82fec664466d585023821c2e39a0c43345669a41244d05018a23d7159515f8ff4d88b01cd0eb83070d0077e065d74d7373816b61505718f8d4f270286a59d45e'),
        ((0x3ae38d4ebf7e7f6dc0a1e31e5efa7ca123fdc321e533e79fedd5132c5999ef5b, 0x36d55dc9edf8669beecd9a2a029092b9, bytes.fromhex('d50ea48c8962962f7c3d301fa9f877245026c204a7771292cddca1e7ffebbef00e86d72910b7d8a756dfb45c9f1040978bb748ca537edd90b670ecee375e15d98582b9f93b6355adc9f80f4fb2108fb9')), '8d22db30c4253c3e3add9685c14d55b05f7cf7626c52cccfcbe9b99fd8913663b8b1f22e277a4cc3d0e7e978a34782eb876867556ad4728486d5e890ea738243e3700a696d6eb58cd81c0e60eb121c50'),
        ((0xd30bfc0b2a19d5b8b6f8f46ab7f444ee136a7fa3fbdaf530cc3e8976339afcc4, 0x80be76a7f885d2c06b37d6a528fae0cd, bytes.fromhex('31e4677a17aed120bd3af69fbb0e4b645b9e8c104e280b799ddd49f1e241c3ccb7d40e1c6ff226bf04f8049c51a86e2981cf1331c824d7d451746ccf77fc22fd3717001ee51913d81f7a06fb0037f309957579f695670f2c4c7397d2d990374e')), '0b6e2a8213169b3b78db6de324e286f0366044e035c6970afbf0a1a5c32a05b24ba706cd9c6609737651a81b2bcf4c681dc0861983a5aec76e6c8b244112d64d489e84328974737394b83a39459011727162652b7aa793bfb1b71488b7dec96b'),
        ((0x64a256a663527ebea71f8d770990b4cee4a2d3afbfd33fb12c7ac300ef59e49a, 0x18cce9147f295c5c00dbe0424089d3b4, bytes.fromhex('d99771963b7ae5202e382ff8c06e035367909cd24fe5ada7f3d39bfaeb5de98b04eaf4989648e00112f0d2aadb8c5f2157b64581450359965140c141e5fb631e43469d65d1b7370eb3b396399fec32cced294a5eee46d6547f7bbd49dee148b4bc31d6c493cfd28f3908e36cb698629d')), 'f7e0f79cfddd15ed3600ab2d29c56ba3c8e96d1a896aff6dec773e6ea4710a77f2f4ec646b76efda6428c175d007c84aa9f4b18c5e1bac5f27f7307b737655eee813f7e1f5880a37ac63ad1666e7883083b648454d45786f53ea3db1b5129291138abe40c79fcb7ab7c6f6b9ea133b5f'),
        ((0x31358e8af34d6ac31c958bbd5c8fb33c334714bffb41700d28b07f11cfe891e7, 0x144516246a752c329056d884daf3c89d, bytes.fromhex('b32e2b171b63827034ebb0d1909f7ef1d51c5f82c1bb9bc26bc4ac4dccdee8357dca6154c2510ae1c87b1b422b02b621bb06cac280023894fcff3406af08ee9be1dd72419beccddff77c722d992cdcc87e9c7486f56ab406ea608d8c6aeb060c64cf2785ad1a159147567e39e303370da445247526d95942bf4d7e88057178b0')), 'cfc155a3967de347f58fa2e8bbeb4183d6d32f7427155e6ab39cddf2e627c572acae02f1f243f3b784e73e21e7e520eacd3befafbee814867334c6ee8c2f0ee7376d3c72728cde7813173dbdfe3357deac41d3ae2a04229c0262f2d109d01f5d03e7f848fb50c28849146c02a2f4ebf7d7ffe3c9d40e31970bf151873672ef2b'),
        ((0x5b4b69339891db4e3337c3486f439dfbd0fb2a782ca71ef0059819d51669d93c, 0x2b28a2d19ba9ecd149dae96622c21769, bytes.fromhex('ba21db8ec170fa4d73cfc381687f3fa188dd2d012bef48007f3dc88329e22ba32fe235a315be362546468b9db6af6705c6e5d4d36822f42883c08d4a994cc454a7db292c4ca1f4b62ebf8e479a5d545d6af9978d2cfee7bc80999192c2c8662ce9b4be11af40bd68f3e2d5685bb28c0f3dc08017c0aba8263e6fdc45ed7f9893bf14fd3a86c418a35c5667e642d59985')), 'a0bb1d2fdeb7e6bf34c690fe7b72a5e9d65796aa57982fe340c286d6923dbddb426566ff58e9c0b3af52e4db446f6cc5daa5bfcf4e3c85db5a5638e670c370cce128db22c97542a64a63846f18a228d3462a11376dcb71f66ec52ebda474f7b6752915b0801797974bc51eb1218127fed60f1009430eb5089fb3ba5f28fad24c518ccddc2501393ceb6dffc46a159421'),
        ((0x87725bd43a45608814180773f0e7ab95a3c859d83a2130e884190e44d14c6996, 0xe49651988ebbb72eb8bb80bb9abbca34, bytes.fromhex('5b97a9d423f4b97413f388d9a341e727bb339f8e18a3fac2f2fb85abdc8f135deb30054a1afdc9b6ed7da16c55eba6b0d4d10c74e1d9a7cf8edfaeaa684ac0bd9f9d24ba674955c79dc6be32aee1c260b558ff07e3a4d49d24162011ff254db8be078e8ad07e648e6bf5679376cb4321a5ef01afe6ad8816fcc7634669c8c4389295c9241e45fff39f3225f7745032daeebe99d4b19bcb215d1bfdb36eda2c24')), 'bfe5c6354b7a3ff3e192e05775b9b75807de12e38a626b8bf0e12d5fff78e4f1775aa7d792d885162e66d88930f9c3b2cdf8654f56972504803190386270f0aa43645db187af41fcea639b1f8026ccdd0c23e0de37094a8b941ecb7602998a4b2604e69fc04219585d854600e0ad6f99a53b2504043c08b1c3e214d17cde053cbdf91daa999ed5b47c37983ba3ee254bc5c793837daaa8c85cfc12f7f54f699f')
            ],
    "eq"
)

tests = TestSet(
        "AES256 tests",
        successful_decryption_1_byte_test,
        unsuccessful_decryption_1_byte_test,
        successful_decryption_32_byte_test,
        unsuccessful_decryption_32_byte_test,
        zero_key_encryption_test,
        zero_key_decryption_failure_test,
        nist_aesavs_GFSbox_test,
        nist_aesavs_KeySBox_test,
        nist_aesavs_VarTxt_test,
        nist_aesavs_VarKey_test,
        nist_aesavs_multiblock_message_test_enc,
        nist_aesavs_multiblock_message_test_dec
    )

if __name__ == "__main__":
    tests.run()
