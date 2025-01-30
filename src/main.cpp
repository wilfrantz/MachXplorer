/* A command-line tool that analyzes Mach-O binaries on macOS,
 * providing insights into headers, segments, symbols,
 * and obfuscation techniques.*/

#include "analyzer.h"

int main(int argc, char **argv)
{
    Analyzer analyzer;
    analyzer.processCLArguments(argc, argv);

    return 0;
}