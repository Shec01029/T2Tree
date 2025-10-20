# T2Tree, Version 1.0
Tested on Ubuntu 22.04.5 LTS
Requirement:
g++ at least version 7.0 (C++17 required)

Installation:
make
or
./build.sh

How to run: ./T2Tree_Project [options]
Usage:
./T2Tree_Project [-r ruleset][-p trace][-b binth][-bit maxbit][-t maxTreenum][-l maxTreeDepth]

Options:
-r ruleset: Rule set file path
-p trace: Packet trace file path
-b binth: LTSS capacity and leaf node threshold (default: 10)
-bit maxbit: Maximum bits per level (default: 2)
-t maxTreenum: Maximum number of subtrees (default: 32)
-l maxTreeDepth: Maximum tree depth (default: 4)
-h: Display help information

Try now:
./T2Tree_Project
or
./T2Tree_Project -r acl_10k -p acl_10k_trace -b 8 -bit 4 -t 32 -l 10

If you have any questions, feel free to contact with me.

2025.10.01
