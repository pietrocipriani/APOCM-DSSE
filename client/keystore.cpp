#include "keystore.hpp"
#include "utils.hpp"
#include "password_utils.hpp"
#include <Monocypher.hh>
#include <fstream>
#include <filesystem>


template<size_t lambda>
void Keystore<lambda>::load_keys() {
    using AE = monocypher::session::encryption_key<monocypher::XChaCha20_Poly1305>;
    using Nonce = monocypher::session::nonce;
    using Mac = monocypher::session::mac;
    using Salt = argon2id::salt;

    // Open the file containing the encypted keys.
    std::filesystem::path key_file("./keys.enc");
    std::ifstream keystream(key_file);

    // TODO: warn in case of wide permissions.

    if (!keystream.good()) {
        throw KeysNotFound("Unable to read the key-file");
        abort();
    }

    // Read the encrypted keys file.
    const size_t size = Salt::byte_count
        + Mac::byte_count + Nonce::byte_count + 4 * lambda
        + decltype(con)::byte_count;
    static_assert(size == 16+16+24+4*lambda+8);
    monocypher::byte_array<size> file_data;
    keystream.read(reinterpret_cast<char*>(file_data.data()), file_data.size());

    if (keystream.gcount() != size) {
        throw CorruptedKeys();
        abort();
    }

    // Split the content into salt | mac | nonce | encrypted data.
    Salt salt(file_data.template range<0, Salt::byte_count>());
    Mac mac(file_data.template range<16, Mac::byte_count>());
    Nonce nonce(file_data.template range<32, Nonce::byte_count>());
    auto data = file_data.template range<56, 4 * lambda + 8>();

    // Read the password for decryption.
    std::array<char, 256> password;
    obtain_secure_password(password, "Insert password: ");
    
    // NOTE: password is wiped.
    auto key = obtain_key(salt, password);

    auto& ad = salt;

    // Check then decrypt the keys.
    auto ok = AE(key).unlock(nonce, mac, data, ad, data.data());
    key.wipe();
    if (!ok) {
        throw CorruptedKeys();
        abort();
    }
    
    // Split the plaintext into the keys and Con.
    key_d = monocypher::secret_byte_array(data.template range<0, lambda>());
    key_g = monocypher::secret_byte_array(data.template range<lambda, lambda>());
    key_t = monocypher::secret_byte_array(data.template range<2*lambda, lambda>());
    key_f = monocypher::secret_byte_array(data.template range<3*lambda, lambda>());
    con = data.template range<4*lambda, 8>();
}

template<size_t lambda>
void Keystore<lambda>::store_keys() {
    // Pick a storing password.
    // NOTE: it is possible to put a new password in order to change it.
    // On production this would require confirmation.
    std::array<char, 256> password;
    obtain_secure_password(password, "Choose password: ");
    
    // NOTE: password is wiped.
    auto [key, salt] = derive_key(password);

    using AE = monocypher::session::encryption_key<monocypher::XChaCha20_Poly1305>;
    using Nonce = monocypher::session::nonce;

    auto data = key_d | key_g | key_t | key_f | con;
    auto ad = salt;
    
    Nonce nonce{};
    auto mac = AE(key).lock(nonce, data, ad, data.data());
    key.wipe();
    wipe_keys();

    auto file_data = salt | mac | nonce | data;

    std::filesystem::path key_file("./keys.enc");
    std::ofstream keystream(key_file);

    if (!keystream.good()) {
        throw std::runtime_error("Unable to write the key-file");
        abort();
    }

    // TODO: manage exceptions.
    keystream.write(reinterpret_cast<const char*>(file_data.data()), file_data.size());

    using std::filesystem::perms;
    std::filesystem::permissions(key_file, perms::owner_write | perms::owner_read);
}


template<size_t lambda>
void Keystore<lambda>::wipe_keys() {
    key_d.wipe();
    key_g.wipe();
    key_f.wipe();
    key_t.wipe();
    con = serialize(-2ULL);
}

template<size_t lambda>
void Keystore<lambda>::create_keys() {
    key_d.randomize();
    key_g.randomize();
    key_f.randomize();
    key_t.randomize();
    con = serialize(-2ULL);
}
