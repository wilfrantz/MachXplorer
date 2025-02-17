#pragma once

#include <iostream>
#include <regex>
#include <string>
#include <cstdlib>
#include <vector>
#include <fstream>
#include <sstream>
#include <cmath>
#include <iomanip>
#include <bitset>
#include <cstdint>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <iterator>
#include <unordered_set>
#include <mach-o/nlist.h>
#include <capstone/capstone.h>

namespace machXplorer
{

    class Analyzer
    {
    public:
        enum class AnalysisType
        {
            HEADER,
            SEGMENT,
            SYMBOL,
            DISASSEMBLY,
            OBFUSCATION,
            HEX,
            COMPARE,
            HELP,
            INVALID
        };
        void printHelpMenu(char **argv);
        AnalysisType setAnalysisType(char **argv);
        void processCLArguments(int argc, char **argv);
        void compareMachOBinaries(const std::string &file1,
                                  const std::string &file2);
        void analyzeMachOBinary(const std::string &file,
                                const std::string &file2 = "",
                                const AnalysisType type = AnalysisType::INVALID);

    private:
        void analyzeHeader(const std::string &file);
        void analyzeSegment(const std::string &file);
        void analyzeSection(const std::string &file);
        void analyzeSymbol(const std::string &file);
        void analyzeDisassembly(const std::string &file);
        void analyzeObfuscation(const std::string &file);
        void analyzeHexDump(const std::string &file);

        // Helper functions
        bool isMachO(const std::string &filePath);
        std::ifstream openFileStream(const std::string &file);
        std::vector<std::string> disassembleMachOFile(const std::string &file);
        bool missingCommonStrings(const std::vector<std::string> &strings);
        std::vector<std::string> disassembleSection(const std::string &file, uint64_t offset, uint64_t size);
        std::vector<std::string> disassembleSection(const std::string &file, uint64_t offset, uint64_t size, cpu_type_t cpuType);

        struct SegmentInfo
        {
            std::string name;
            std::vector<uint8_t> data;
        };

        bool isSuspiciousSegment(const SegmentInfo &segment);
        void printWarning(const std::string &message);

        // Functions to print the Mach-O information
        void printSectionInfo(const section_64 *section64);
        void printHeaderInfo(const mach_header_64 *header64);
        void printSegmentInfo(const segment_command_64 *segment64);
        void printSymbolInfo(const symtab_command &symtab64);
        void printDisassemblyInfo(const dysymtab_command &dysymtab);
        std::string formatProtectionFlags(int prot);

    private:

        // NOTE:  Obfuscation Detection Helpers

        /// Step 1: Check if the Mach-O binary has stripped symbols
        bool checkStrippedSymbols(const std::string &file);

        /// Step 2: Detect mangled or obfuscated symbols
        bool checkMangledSymbols(const std::string &file);

        /// Step 3: Detect excessive indirect function calls
        bool checkIndirectCalls(const std::string &file);

        /// Step 4: Detect excessive jump instructions (junk code)
        bool checkJumpInstructions(const std::string &file);

        /// Step 5: Detect packed or encrypted sections based on entropy analysis
        bool checkPackedSections(const std::string &file);

        /// Step 6: Detect suspicious dynamic API resolution
        bool checkDynamicAPIUsage(const std::string &file);

        /// Step 7: Detect high-entropy strings (possible encrypted or XOR-obfuscated strings)
        bool checkObfuscatedStrings(const std::string &file);

        /// Helper: Calculate entropy of a byte sequence to detect encryption or packing
        double calculateEntropy(const std::vector<uint8_t> &data);

        /// Helper: Extract symbol table from Mach-O binary
        std::vector<std::string> extractSymbolTable(const std::string &file);

        /// Helper: Extract all functions dynamically loaded via dylib resolution
        std::vector<std::string> extractDylibFunctions(const std::string &file);

        /// Helper: Extract raw strings from the binary for analysis
        std::vector<std::string> extractStrings(const std::string &file);

        /// Helper: Count the number of jump instructions in a disassembled file
        int countJumpInstructions(const std::vector<std::string> &disassembly);

        /// Helper: Check if an instruction is an indirect function call
        bool isIndirectCall(const std::string &instruction);

        /// Helper: Extract Mach-O segment information (used for packed section detection)
        std::vector<Analyzer::SegmentInfo> extractSegmentInfo(const std::string &file);
    };

} // namespace machXplorer