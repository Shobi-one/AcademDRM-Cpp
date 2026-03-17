#pragma once

#include "drm/virtual_machine.hpp"

#include <cctype>
#include <cstdlib>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace drm::vm {

class ScriptBytecodeCompiler {
public:
    static BytecodeProgram compile(const std::string& script_source) {
        std::vector<std::string> lines = splitLines(script_source);
        std::vector<Instruction> program;
        std::unordered_map<std::string, std::size_t> labels;
        std::vector<PendingJump> pending_jumps;

        for (std::size_t line_index = 0; line_index < lines.size(); ++line_index) {
            const std::string cleaned = stripComment(trim(lines[line_index]));
            if (cleaned.empty()) {
                continue;
            }

            if (isLabelDefinition(cleaned)) {
                const std::string label = trim(cleaned.substr(0, cleaned.size() - 1));
                if (label.empty()) {
                    throw std::runtime_error(errorAt(line_index, "Label name cannot be empty"));
                }
                if (labels.count(label) > 0) {
                    throw std::runtime_error(errorAt(line_index, "Duplicate label: " + label));
                }
                labels[label] = program.size();
                continue;
            }

            const std::vector<std::string> tokens = splitTokens(cleaned);
            if (tokens.empty()) {
                continue;
            }

            const std::string op = normalizeOp(tokens[0]);
            if (op == "PUSH") {
                expectArgCount(tokens, 2, line_index);
                program.push_back(Instruction{ OpCode::PUSH_CONST, parseNumber(tokens[1], line_index) });
            } else if (op == "LOAD") {
                expectArgCount(tokens, 2, line_index);
                program.push_back(Instruction{ OpCode::LOAD_REG, parseRegister(tokens[1], line_index) });
            } else if (op == "STORE") {
                expectArgCount(tokens, 2, line_index);
                program.push_back(Instruction{ OpCode::STORE_REG, parseRegister(tokens[1], line_index) });
            } else if (op == "ADD") {
                expectArgCount(tokens, 1, line_index);
                program.push_back(Instruction{ OpCode::ADD, 0.0 });
            } else if (op == "SUB") {
                expectArgCount(tokens, 1, line_index);
                program.push_back(Instruction{ OpCode::SUB, 0.0 });
            } else if (op == "MUL") {
                expectArgCount(tokens, 1, line_index);
                program.push_back(Instruction{ OpCode::MUL, 0.0 });
            } else if (op == "DIV") {
                expectArgCount(tokens, 1, line_index);
                program.push_back(Instruction{ OpCode::DIV, 0.0 });
            } else if (op == "CMP_LT") {
                expectArgCount(tokens, 1, line_index);
                program.push_back(Instruction{ OpCode::CMP_LT, 0.0 });
            } else if (op == "CMP_GT") {
                expectArgCount(tokens, 1, line_index);
                program.push_back(Instruction{ OpCode::CMP_GT, 0.0 });
            } else if (op == "CMP_EQ") {
                expectArgCount(tokens, 1, line_index);
                program.push_back(Instruction{ OpCode::CMP_EQ, 0.0 });
            } else if (op == "JMP") {
                expectArgCount(tokens, 2, line_index);
                program.push_back(Instruction{ OpCode::JMP, 0.0 });
                pending_jumps.push_back(PendingJump{ program.size() - 1, tokens[1], line_index });
            } else if (op == "JMP_IF_TRUE") {
                expectArgCount(tokens, 2, line_index);
                program.push_back(Instruction{ OpCode::JMP_IF_TRUE, 0.0 });
                pending_jumps.push_back(PendingJump{ program.size() - 1, tokens[1], line_index });
            } else if (op == "JMP_IF_FALSE") {
                expectArgCount(tokens, 2, line_index);
                program.push_back(Instruction{ OpCode::JMP_IF_FALSE, 0.0 });
                pending_jumps.push_back(PendingJump{ program.size() - 1, tokens[1], line_index });
            } else if (op == "CALL") {
                expectArgCount(tokens, 2, line_index);
                program.push_back(Instruction{ OpCode::CALL_HOST, parseHost(tokens[1], line_index) });
            } else if (op == "HALT") {
                expectArgCount(tokens, 1, line_index);
                program.push_back(Instruction{ OpCode::HALT, 0.0 });
            } else {
                throw std::runtime_error(errorAt(line_index, "Unknown opcode: " + tokens[0]));
            }
        }

        resolveJumps(program, labels, pending_jumps);
        return BytecodeCodec::encode(program);
    }

private:
    struct PendingJump {
        std::size_t instruction_index;
        std::string target;
        std::size_t line_index;
    };

    static std::vector<std::string> splitLines(const std::string& text) {
        std::vector<std::string> lines;
        std::stringstream stream(text);
        std::string line;
        while (std::getline(stream, line)) {
            lines.push_back(line);
        }
        if (!text.empty() && text.back() == '\n') {
            lines.push_back(std::string());
        }
        return lines;
    }

    static std::string trim(const std::string& value) {
        std::size_t start = 0;
        while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start])) != 0) {
            ++start;
        }

        std::size_t end = value.size();
        while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
            --end;
        }

        return value.substr(start, end - start);
    }

    static std::string stripComment(const std::string& value) {
        const std::size_t hash_pos = value.find('#');
        const std::size_t slash_pos = value.find("//");

        std::size_t cut = std::string::npos;
        if (hash_pos != std::string::npos) {
            cut = hash_pos;
        }
        if (slash_pos != std::string::npos && (cut == std::string::npos || slash_pos < cut)) {
            cut = slash_pos;
        }

        if (cut == std::string::npos) {
            return value;
        }
        return trim(value.substr(0, cut));
    }

    static bool isLabelDefinition(const std::string& value) {
        return !value.empty() && value.back() == ':';
    }

    static std::vector<std::string> splitTokens(const std::string& line) {
        std::vector<std::string> tokens;
        std::stringstream stream(line);
        std::string token;
        while (stream >> token) {
            tokens.push_back(token);
        }
        return tokens;
    }

    static std::string normalizeOp(const std::string& op) {
        std::string normalized = op;
        for (char& c : normalized) {
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
        return normalized;
    }

    static void expectArgCount(const std::vector<std::string>& tokens, std::size_t expected_count, std::size_t line_index) {
        if (tokens.size() != expected_count) {
            throw std::runtime_error(errorAt(line_index, "Invalid argument count for opcode " + tokens[0]));
        }
    }

    static double parseNumber(const std::string& token, std::size_t line_index) {
        char* end_ptr = nullptr;
        const double parsed = std::strtod(token.c_str(), &end_ptr);
        if (end_ptr == token.c_str() || *end_ptr != '\0') {
            throw std::runtime_error(errorAt(line_index, "Invalid numeric operand: " + token));
        }
        return parsed;
    }

    static double parseRegister(const std::string& token, std::size_t line_index) {
        std::string value = token;
        if (!value.empty() && (value[0] == 'r' || value[0] == 'R')) {
            value = value.substr(1);
        }

        const double index = parseInteger(value, line_index, "register index");
        if (index < 0.0) {
            throw std::runtime_error(errorAt(line_index, "Register index cannot be negative"));
        }
        return index;
    }

    static double parseHost(const std::string& token, std::size_t line_index) {
        std::string value = token;
        if (value.size() > 4 && (value[0] == 'h' || value[0] == 'H')) {
            std::string prefix = value.substr(0, 4);
            for (char& c : prefix) {
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            }
            if (prefix == "host") {
                value = value.substr(4);
            }
        }

        const double index = parseInteger(value, line_index, "host callback index");
        if (index < 0.0) {
            throw std::runtime_error(errorAt(line_index, "Host callback index cannot be negative"));
        }
        return index;
    }

    static double parseInteger(const std::string& token, std::size_t line_index, const std::string& type_name) {
        char* end_ptr = nullptr;
        const long long parsed = std::strtoll(token.c_str(), &end_ptr, 10);
        if (end_ptr == token.c_str() || *end_ptr != '\0') {
            throw std::runtime_error(errorAt(line_index, "Invalid " + type_name + ": " + token));
        }
        return static_cast<double>(parsed);
    }

    static void resolveJumps(
        std::vector<Instruction>& program,
        const std::unordered_map<std::string, std::size_t>& labels,
        const std::vector<PendingJump>& pending_jumps) {

        for (const PendingJump& jump : pending_jumps) {
            const auto label_it = labels.find(jump.target);
            if (label_it != labels.end()) {
                program[jump.instruction_index].operand = static_cast<double>(label_it->second);
                continue;
            }

            const double direct_index = parseInteger(jump.target, jump.line_index, "jump target");
            if (direct_index < 0.0 || static_cast<std::size_t>(direct_index) >= program.size()) {
                throw std::runtime_error(errorAt(jump.line_index, "Jump target out of range: " + jump.target));
            }
            program[jump.instruction_index].operand = direct_index;
        }
    }

    static std::string errorAt(std::size_t line_index, const std::string& message) {
        return "Script compile error at line " + std::to_string(line_index + 1) + ": " + message;
    }
};

} // namespace drm::vm
