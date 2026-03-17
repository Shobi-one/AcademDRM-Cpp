#pragma once

#include <cstddef>
#include <cstdint>
#include <array>
#include <functional>
#include <cmath>
#include <stdexcept>
#include <string>
#include <vector>

#if defined(__has_include)
#if __has_include(<openssl/evp.h>) && __has_include(<openssl/aes.h>)
#define DRM_VM_HAS_OPENSSL 1
#include <openssl/evp.h>
#include <openssl/aes.h>
#endif
#endif

namespace drm::vm {

enum class OpCode : std::uint8_t {
    PUSH_CONST,
    LOAD_REG,
    STORE_REG,
    ADD,
    SUB,
    MUL,
    DIV,
    CMP_LT,
    CMP_GT,
    CMP_EQ,
    JMP,
    JMP_IF_TRUE,
    JMP_IF_FALSE,
    CALL_HOST,
    HALT
};

struct Instruction {
    OpCode opcode;
    double operand;
};

class BytecodeProgram {
public:
    explicit BytecodeProgram(std::vector<std::uint8_t> bytes)
        : bytes_(std::move(bytes)) {}

    const std::vector<std::uint8_t>& bytes() const { return bytes_; }

private:
    std::vector<std::uint8_t> bytes_;
};

enum class EncryptionAlgorithm : std::uint8_t {
    XOR = 1,
    AES_256_CBC = 2
};

class EncryptedBytecodeProgram {
public:
    EncryptedBytecodeProgram(
        EncryptionAlgorithm algorithm,
        std::vector<std::uint8_t> iv,
        std::vector<std::uint8_t> encrypted_bytes,
        std::uint32_t integrity_tag)
        : algorithm_(algorithm),
          iv_(std::move(iv)),
          encrypted_bytes_(std::move(encrypted_bytes)),
          integrity_tag_(integrity_tag) {}

    EncryptionAlgorithm algorithm() const { return algorithm_; }
    const std::vector<std::uint8_t>& iv() const { return iv_; }
    const std::vector<std::uint8_t>& encryptedBytes() const { return encrypted_bytes_; }
    std::uint32_t integrityTag() const { return integrity_tag_; }

private:
    EncryptionAlgorithm algorithm_;
    std::vector<std::uint8_t> iv_;
    std::vector<std::uint8_t> encrypted_bytes_;
    std::uint32_t integrity_tag_;
};

class BytecodeEncryption {
public:
    static EncryptedBytecodeProgram encrypt(
        const BytecodeProgram& plain,
        const std::vector<std::uint8_t>& key,
        EncryptionAlgorithm algorithm = EncryptionAlgorithm::XOR) {

        if (key.empty()) {
            throw std::runtime_error("Encryption key cannot be empty");
        }

        std::vector<std::uint8_t> iv = buildIv(key, algorithm);
        std::vector<std::uint8_t> encrypted;

        switch (algorithm) {
            case EncryptionAlgorithm::XOR:
                encrypted = xorCipher(plain.bytes(), key, iv);
                break;
            case EncryptionAlgorithm::AES_256_CBC:
                encrypted = aesEncrypt(plain.bytes(), key, iv);
                break;
            default:
                throw std::runtime_error("Unsupported bytecode encryption algorithm");
        }

        const std::uint32_t tag = computeIntegrityTag(algorithm, iv, encrypted, key);
        return EncryptedBytecodeProgram(algorithm, std::move(iv), std::move(encrypted), tag);
    }

    static BytecodeProgram decrypt(
        const EncryptedBytecodeProgram& encrypted,
        const std::vector<std::uint8_t>& key) {

        if (key.empty()) {
            throw std::runtime_error("Decryption key cannot be empty");
        }

        const std::uint32_t expected = computeIntegrityTag(
            encrypted.algorithm(),
            encrypted.iv(),
            encrypted.encryptedBytes(),
            key);

        if (expected != encrypted.integrityTag()) {
            throw std::runtime_error("Encrypted bytecode integrity check failed");
        }

        std::vector<std::uint8_t> plain;
        switch (encrypted.algorithm()) {
            case EncryptionAlgorithm::XOR:
                plain = xorCipher(encrypted.encryptedBytes(), key, encrypted.iv());
                break;
            case EncryptionAlgorithm::AES_256_CBC:
                plain = aesDecrypt(encrypted.encryptedBytes(), key, encrypted.iv());
                break;
            default:
                throw std::runtime_error("Unsupported bytecode encryption algorithm");
        }

        return BytecodeProgram(std::move(plain));
    }

private:
    static std::vector<std::uint8_t> buildIv(
        const std::vector<std::uint8_t>& key,
        EncryptionAlgorithm algorithm) {

        const std::size_t iv_size = (algorithm == EncryptionAlgorithm::AES_256_CBC) ? 16 : 8;
        std::vector<std::uint8_t> iv(iv_size, 0u);
        std::uint32_t seed = fnv1a32(key.data(), key.size());

        for (std::size_t i = 0; i < iv.size(); ++i) {
            seed ^= static_cast<std::uint32_t>((i + 1) * 0x9E3779B1u);
            seed *= 16777619u;
            iv[i] = static_cast<std::uint8_t>((seed >> ((i % 4) * 8)) & 0xFFu);
        }

        return iv;
    }

    static std::vector<std::uint8_t> xorCipher(
        const std::vector<std::uint8_t>& input,
        const std::vector<std::uint8_t>& key,
        const std::vector<std::uint8_t>& iv) {

        std::vector<std::uint8_t> out(input.size(), 0u);
        for (std::size_t i = 0; i < input.size(); ++i) {
            const std::uint8_t k = key[i % key.size()];
            const std::uint8_t v = iv[i % iv.size()];
            const std::uint8_t stream = static_cast<std::uint8_t>(k ^ v ^ static_cast<std::uint8_t>((i * 131u) & 0xFFu));
            out[i] = static_cast<std::uint8_t>(input[i] ^ stream);
        }
        return out;
    }

    static std::uint32_t computeIntegrityTag(
        EncryptionAlgorithm algorithm,
        const std::vector<std::uint8_t>& iv,
        const std::vector<std::uint8_t>& encrypted,
        const std::vector<std::uint8_t>& key) {

        std::uint32_t hash = 2166136261u;
        hash = fnv1a32Update(hash, static_cast<std::uint8_t>(algorithm));
        hash = fnv1a32Update(hash, iv.data(), iv.size());
        hash = fnv1a32Update(hash, encrypted.data(), encrypted.size());
        hash = fnv1a32Update(hash, key.data(), key.size());
        return hash;
    }

    static std::uint32_t fnv1a32(const std::uint8_t* data, std::size_t size) {
        std::uint32_t hash = 2166136261u;
        return fnv1a32Update(hash, data, size);
    }

    static std::uint32_t fnv1a32Update(std::uint32_t hash, std::uint8_t byte) {
        hash ^= static_cast<std::uint32_t>(byte);
        hash *= 16777619u;
        return hash;
    }

    static std::uint32_t fnv1a32Update(std::uint32_t hash, const std::uint8_t* data, std::size_t size) {
        for (std::size_t i = 0; i < size; ++i) {
            hash ^= static_cast<std::uint32_t>(data[i]);
            hash *= 16777619u;
        }
        return hash;
    }

    static std::array<std::uint8_t, 32> deriveAesKey(const std::vector<std::uint8_t>& key) {
        std::array<std::uint8_t, 32> aes_key{};
        std::uint32_t seed = fnv1a32(key.data(), key.size());
        for (std::size_t i = 0; i < aes_key.size(); ++i) {
            seed ^= static_cast<std::uint32_t>((i + 1) * 0x85EBCA77u);
            seed = (seed << 13) | (seed >> 19);
            seed ^= static_cast<std::uint32_t>(key[i % key.size()]);
            aes_key[i] = static_cast<std::uint8_t>((seed >> ((i % 4) * 8)) & 0xFFu);
        }
        return aes_key;
    }

    static std::vector<std::uint8_t> aesEncrypt(
        const std::vector<std::uint8_t>& plain,
        const std::vector<std::uint8_t>& key,
        const std::vector<std::uint8_t>& iv) {
#if defined(DRM_VM_HAS_OPENSSL)
        if (iv.size() != 16) {
            throw std::runtime_error("AES-256-CBC requires 16-byte IV");
        }

        const std::array<std::uint8_t, 32> aes_key = deriveAesKey(key);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (ctx == nullptr) {
            throw std::runtime_error("Failed to create OpenSSL cipher context");
        }

        std::vector<std::uint8_t> output(plain.size() + AES_BLOCK_SIZE);
        int out_len1 = 0;
        int out_len2 = 0;

        const int init_ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aes_key.data(), iv.data());
        const int update_ok = init_ok ? EVP_EncryptUpdate(
            ctx,
            output.data(),
            &out_len1,
            plain.data(),
            static_cast<int>(plain.size())) : 0;
        const int final_ok = update_ok ? EVP_EncryptFinal_ex(ctx, output.data() + out_len1, &out_len2) : 0;

        EVP_CIPHER_CTX_free(ctx);

        if (final_ok != 1) {
            throw std::runtime_error("OpenSSL AES encryption failed");
        }

        output.resize(static_cast<std::size_t>(out_len1 + out_len2));
        return output;
#else
        (void)plain;
        (void)key;
        (void)iv;
        throw std::runtime_error("AES encryption requested, but OpenSSL headers are unavailable");
#endif
    }

    static std::vector<std::uint8_t> aesDecrypt(
        const std::vector<std::uint8_t>& encrypted,
        const std::vector<std::uint8_t>& key,
        const std::vector<std::uint8_t>& iv) {
#if defined(DRM_VM_HAS_OPENSSL)
        if (iv.size() != 16) {
            throw std::runtime_error("AES-256-CBC requires 16-byte IV");
        }

        const std::array<std::uint8_t, 32> aes_key = deriveAesKey(key);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (ctx == nullptr) {
            throw std::runtime_error("Failed to create OpenSSL cipher context");
        }

        std::vector<std::uint8_t> output(encrypted.size() + AES_BLOCK_SIZE);
        int out_len1 = 0;
        int out_len2 = 0;

        const int init_ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aes_key.data(), iv.data());
        const int update_ok = init_ok ? EVP_DecryptUpdate(
            ctx,
            output.data(),
            &out_len1,
            encrypted.data(),
            static_cast<int>(encrypted.size())) : 0;
        const int final_ok = update_ok ? EVP_DecryptFinal_ex(ctx, output.data() + out_len1, &out_len2) : 0;

        EVP_CIPHER_CTX_free(ctx);

        if (final_ok != 1) {
            throw std::runtime_error("OpenSSL AES decryption failed");
        }

        output.resize(static_cast<std::size_t>(out_len1 + out_len2));
        return output;
#else
        (void)encrypted;
        (void)key;
        (void)iv;
        throw std::runtime_error("AES decryption requested, but OpenSSL headers are unavailable");
#endif
    }
};

class BytecodeCodec {
public:
    static BytecodeProgram encode(const std::vector<Instruction>& program) {
        std::vector<std::uint8_t> bytes;
        bytes.reserve(kHeaderSize + program.size() * kInstructionSize);

        appendHeader(bytes, static_cast<std::uint32_t>(program.size()));
        for (const Instruction& inst : program) {
            appendInstruction(bytes, inst);
        }

        return BytecodeProgram(std::move(bytes));
    }

    static std::vector<Instruction> decode(const BytecodeProgram& encoded) {
        const std::vector<std::uint8_t>& bytes = encoded.bytes();
        if (bytes.size() < kHeaderSize) {
            throw std::runtime_error("Bytecode is too small");
        }

        validateHeader(bytes);
        const std::uint32_t count = readU32(bytes, 5);

        const std::size_t expected_size = kHeaderSize + static_cast<std::size_t>(count) * kInstructionSize;
        if (bytes.size() != expected_size) {
            throw std::runtime_error("Bytecode size does not match header instruction count");
        }

        std::vector<Instruction> decoded;
        decoded.reserve(count);

        std::size_t cursor = kHeaderSize;
        for (std::uint32_t i = 0; i < count; ++i) {
            decoded.push_back(readInstruction(bytes, cursor));
            cursor += kInstructionSize;
        }

        return decoded;
    }

private:
    static constexpr std::size_t kHeaderSize = 9;
    static constexpr std::size_t kInstructionSize = 10;
    static constexpr std::int64_t kOperandScale = 1000000;

    static constexpr std::uint8_t kMagic0 = 'A';
    static constexpr std::uint8_t kMagic1 = 'D';
    static constexpr std::uint8_t kMagic2 = 'V';
    static constexpr std::uint8_t kMagic3 = 'M';
    static constexpr std::uint8_t kVersion = 1;

    static constexpr std::uint8_t kXorKeyOpcode = 0x5A;
    static constexpr std::uint8_t kXorKeyOperand = 0xC3;

    static std::uint8_t opToToken(OpCode op) {
        switch (op) {
            case OpCode::PUSH_CONST: return 0xA7;
            case OpCode::LOAD_REG: return 0x39;
            case OpCode::STORE_REG: return 0xF1;
            case OpCode::ADD: return 0x11;
            case OpCode::SUB: return 0x12;
            case OpCode::MUL: return 0x13;
            case OpCode::DIV: return 0x14;
            case OpCode::CMP_LT: return 0x31;
            case OpCode::CMP_GT: return 0x32;
            case OpCode::CMP_EQ: return 0x33;
            case OpCode::JMP: return 0x7C;
            case OpCode::JMP_IF_TRUE: return 0x7D;
            case OpCode::JMP_IF_FALSE: return 0x7E;
            case OpCode::CALL_HOST: return 0xC9;
            case OpCode::HALT: return 0xEE;
            default:
                throw std::runtime_error("Unknown opcode while encoding bytecode");
        }
    }

    static OpCode tokenToOp(std::uint8_t token) {
        switch (token) {
            case 0xA7: return OpCode::PUSH_CONST;
            case 0x39: return OpCode::LOAD_REG;
            case 0xF1: return OpCode::STORE_REG;
            case 0x11: return OpCode::ADD;
            case 0x12: return OpCode::SUB;
            case 0x13: return OpCode::MUL;
            case 0x14: return OpCode::DIV;
            case 0x31: return OpCode::CMP_LT;
            case 0x32: return OpCode::CMP_GT;
            case 0x33: return OpCode::CMP_EQ;
            case 0x7C: return OpCode::JMP;
            case 0x7D: return OpCode::JMP_IF_TRUE;
            case 0x7E: return OpCode::JMP_IF_FALSE;
            case 0xC9: return OpCode::CALL_HOST;
            case 0xEE: return OpCode::HALT;
            default:
                throw std::runtime_error("Unknown opcode token in bytecode");
        }
    }

    static void appendHeader(std::vector<std::uint8_t>& bytes, std::uint32_t count) {
        bytes.push_back(kMagic0);
        bytes.push_back(kMagic1);
        bytes.push_back(kMagic2);
        bytes.push_back(kMagic3);
        bytes.push_back(kVersion);
        appendU32(bytes, count);
    }

    static void validateHeader(const std::vector<std::uint8_t>& bytes) {
        if (bytes[0] != kMagic0 || bytes[1] != kMagic1 || bytes[2] != kMagic2 || bytes[3] != kMagic3) {
            throw std::runtime_error("Invalid bytecode magic header");
        }
        if (bytes[4] != kVersion) {
            throw std::runtime_error("Unsupported bytecode version");
        }
    }

    static void appendInstruction(std::vector<std::uint8_t>& bytes, const Instruction& inst) {
        const std::uint8_t token = opToToken(inst.opcode) ^ kXorKeyOpcode;
        bytes.push_back(token);
        bytes.push_back(0x01);

        const std::int64_t fixed = static_cast<std::int64_t>(std::llround(inst.operand * static_cast<double>(kOperandScale)));
        appendI64(bytes, fixed ^ static_cast<std::int64_t>(kXorKeyOperand));
    }

    static Instruction readInstruction(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
        if (bytes[offset + 1] != 0x01) {
            throw std::runtime_error("Invalid bytecode operand encoding type");
        }

        const std::uint8_t token = bytes[offset] ^ kXorKeyOpcode;
        const OpCode op = tokenToOp(token);

        const std::int64_t encoded_operand = readI64(bytes, offset + 2);
        const std::int64_t fixed = encoded_operand ^ static_cast<std::int64_t>(kXorKeyOperand);
        const double operand = static_cast<double>(fixed) / static_cast<double>(kOperandScale);

        return Instruction{ op, operand };
    }

    static void appendU32(std::vector<std::uint8_t>& bytes, std::uint32_t value) {
        bytes.push_back(static_cast<std::uint8_t>(value & 0xFFu));
        bytes.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
        bytes.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFFu));
        bytes.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFFu));
    }

    static std::uint32_t readU32(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
        return static_cast<std::uint32_t>(bytes[offset]) |
               (static_cast<std::uint32_t>(bytes[offset + 1]) << 8) |
               (static_cast<std::uint32_t>(bytes[offset + 2]) << 16) |
               (static_cast<std::uint32_t>(bytes[offset + 3]) << 24);
    }

    static void appendI64(std::vector<std::uint8_t>& bytes, std::int64_t value) {
        for (int i = 0; i < 8; ++i) {
            bytes.push_back(static_cast<std::uint8_t>((static_cast<std::uint64_t>(value) >> (8 * i)) & 0xFFu));
        }
    }

    static std::int64_t readI64(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
        std::uint64_t value = 0;
        for (int i = 0; i < 8; ++i) {
            value |= (static_cast<std::uint64_t>(bytes[offset + i]) << (8 * i));
        }
        return static_cast<std::int64_t>(value);
    }
};

class VirtualMachine {
public:
    using HostCallback = std::function<void(VirtualMachine&)>;

    explicit VirtualMachine(std::size_t register_count)
        : ip_(0), halted_(false), registers_(register_count, 0.0) {}

    void loadProgram(const std::vector<Instruction>& program) {
        program_ = program;
        resetState();
    }

    void loadBytecodeProgram(const BytecodeProgram& encoded_program) {
        program_ = BytecodeCodec::decode(encoded_program);
        resetState();
    }

    void loadEncryptedBytecodeProgram(
        const EncryptedBytecodeProgram& encrypted_program,
        const std::vector<std::uint8_t>& key) {

        const BytecodeProgram decrypted = BytecodeEncryption::decrypt(encrypted_program, key);
        loadBytecodeProgram(decrypted);
    }

    void setHostCallbacks(const std::vector<HostCallback>& callbacks) {
        host_callbacks_ = callbacks;
    }

    void run() {
        while (!halted_) {
            if (ip_ >= program_.size()) {
                throw std::runtime_error("VM instruction pointer out of bounds");
            }

            const Instruction& inst = program_[ip_];
            dispatch(inst);
        }
    }

    void halt() { halted_ = true; }

    void push(double value) { stack_.push_back(value); }

    double pop() {
        if (stack_.empty()) {
            throw std::runtime_error("VM stack underflow");
        }
        const double value = stack_.back();
        stack_.pop_back();
        return value;
    }

    double peek() const {
        if (stack_.empty()) {
            throw std::runtime_error("VM stack is empty");
        }
        return stack_.back();
    }

    double registerAt(std::size_t index) const {
        validateRegisterIndex(index);
        return registers_[index];
    }

    void setRegister(std::size_t index, double value) {
        validateRegisterIndex(index);
        registers_[index] = value;
    }

    std::size_t instructionPointer() const { return ip_; }

private:
    void resetState() {
        ip_ = 0;
        halted_ = false;
        stack_.clear();
        for (double& reg : registers_) {
            reg = 0.0;
        }
    }

    void validateRegisterIndex(std::size_t index) const {
        if (index >= registers_.size()) {
            throw std::runtime_error("VM register index out of range");
        }
    }

    std::size_t asIndexOperand(double operand) const {
        if (operand < 0.0) {
            throw std::runtime_error("VM operand cannot be negative for index ops");
        }

        const auto index = static_cast<std::size_t>(operand);
        if (static_cast<double>(index) != operand) {
            throw std::runtime_error("VM index operand must be an integer value");
        }
        return index;
    }

    void binaryArithmetic(const std::function<double(double, double)>& fn) {
        const double rhs = pop();
        const double lhs = pop();
        push(fn(lhs, rhs));
        ++ip_;
    }

    void dispatch(const Instruction& inst) {
        switch (inst.opcode) {
            case OpCode::PUSH_CONST:
                push(inst.operand);
                ++ip_;
                break;
            case OpCode::LOAD_REG: {
                const std::size_t reg = asIndexOperand(inst.operand);
                push(registerAt(reg));
                ++ip_;
                break;
            }
            case OpCode::STORE_REG: {
                const std::size_t reg = asIndexOperand(inst.operand);
                setRegister(reg, pop());
                ++ip_;
                break;
            }
            case OpCode::ADD:
                binaryArithmetic([](double lhs, double rhs) { return lhs + rhs; });
                break;
            case OpCode::SUB:
                binaryArithmetic([](double lhs, double rhs) { return lhs - rhs; });
                break;
            case OpCode::MUL:
                binaryArithmetic([](double lhs, double rhs) { return lhs * rhs; });
                break;
            case OpCode::DIV:
                binaryArithmetic([](double lhs, double rhs) {
                    if (rhs == 0.0) {
                        throw std::runtime_error("VM division by zero");
                    }
                    return lhs / rhs;
                });
                break;
            case OpCode::CMP_LT:
                binaryArithmetic([](double lhs, double rhs) { return lhs < rhs ? 1.0 : 0.0; });
                break;
            case OpCode::CMP_GT:
                binaryArithmetic([](double lhs, double rhs) { return lhs > rhs ? 1.0 : 0.0; });
                break;
            case OpCode::CMP_EQ:
                binaryArithmetic([](double lhs, double rhs) { return lhs == rhs ? 1.0 : 0.0; });
                break;
            case OpCode::JMP: {
                const std::size_t target = asIndexOperand(inst.operand);
                if (target >= program_.size()) {
                    throw std::runtime_error("VM jump target out of range");
                }
                ip_ = target;
                break;
            }
            case OpCode::JMP_IF_TRUE: {
                const double condition = pop();
                if (condition != 0.0) {
                    const std::size_t target = asIndexOperand(inst.operand);
                    if (target >= program_.size()) {
                        throw std::runtime_error("VM jump target out of range");
                    }
                    ip_ = target;
                } else {
                    ++ip_;
                }
                break;
            }
            case OpCode::JMP_IF_FALSE: {
                const double condition = pop();
                if (condition == 0.0) {
                    const std::size_t target = asIndexOperand(inst.operand);
                    if (target >= program_.size()) {
                        throw std::runtime_error("VM jump target out of range");
                    }
                    ip_ = target;
                } else {
                    ++ip_;
                }
                break;
            }
            case OpCode::CALL_HOST: {
                const std::size_t host_index = asIndexOperand(inst.operand);
                if (host_index >= host_callbacks_.size()) {
                    throw std::runtime_error("VM host callback index out of range");
                }
                host_callbacks_[host_index](*this);
                ++ip_;
                break;
            }
            case OpCode::HALT:
                halt();
                break;
            default:
                throw std::runtime_error("VM encountered unknown opcode");
        }
    }

    std::size_t ip_;
    bool halted_;
    std::vector<double> stack_;
    std::vector<double> registers_;
    std::vector<Instruction> program_;
    std::vector<HostCallback> host_callbacks_;
};

} // namespace drm::vm
