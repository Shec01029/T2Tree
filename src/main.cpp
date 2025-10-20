#include <iostream>
#include <cstdio>
#include <fstream>
#include <cstring>
#include <map>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <numeric>
#include <queue>
#include <climits>
#include <algorithm>
#include "./T2Tree/T2Tree.h"
#include "./T2Tree/Tools.h"

using namespace std;

// // 
// bool DEBUG_MODE = false;
// bool VERIFY_CLASSIFICATION = false;

FILE *fpr = fopen("./acl_10k", "r");
FILE *fpt = fopen("./acl_10k_trace", "r");
string ruleName;

int binth = 8;       
int maxTree = 32;
int maxBits = 4;     
int maxLevel = 6;    
int wrsThreshold = -1;

int rand_update[MAXRULES];

int getRecommendedWRSThreshold(int ruleCount, int binth) {
    int baseThreshold;
    
    if (ruleCount < 10001) {
        baseThreshold = 90;
    } else {
        baseThreshold = 20;
    }
    
    if (binth >= 32) {
        baseThreshold = static_cast<int>(baseThreshold * 2.0);
    } else if (binth >= 16) {
        baseThreshold = static_cast<int>(baseThreshold * 1.5);
    }
    
    return baseThreshold;
}

// // 
// int bruteForceClassify(const vector<Rule>& rules, const Packet& packet) {
//     int bestPriority = -1;
//     for (const Rule& rule : rules) {
//         if (rule.MatchesPacket(packet)) {
//             bestPriority = std::max(bestPriority, rule.priority);
//         }
//     }
//     return bestPriority;
// }

// // 
// void analyzeClassificationError(const Rule& expectedRule, int actualPriority, 
//                                 const vector<Rule>& allRules, const Packet& packet) {
//     printf("=== Misclassification Details ===\n");
//     printf("Expected rule: ID=%d, Priority=%d\n", expectedRule.id, expectedRule.priority);
//     printf("Actual returned priority: %d\n", actualPriority);
//     
//     // Find actually matching rules
//     vector<Rule> matchingRules;
//     for (const Rule& rule : allRules) {
//         if (rule.MatchesPacket(packet)) {
//             matchingRules.push_back(rule);
//         }
//     }
//     
//     sort(matchingRules.begin(), matchingRules.end(),
//          [](const Rule& a, const Rule& b) { return a.priority > b.priority; });
//     
//     printf("All matching rules (sorted by priority):\n");
//     int count = 0;
//     for (const Rule& rule : matchingRules) {
//         printf("  Rule%d: Priority=%d\n", rule.id, rule.priority);
//         if (++count >= 5) break;  // Only show first 5
//     }
//     printf("==================\n");
// }

vector<Rule> loadrule(FILE *fp) {
    unsigned int tmp;
    unsigned sip1, sip2, sip3, sip4, smask;
    unsigned dip1, dip2, dip3, dip4, dmask;
    unsigned sport1, sport2;
    unsigned dport1, dport2;
    unsigned protocal, protocol_mask;
    unsigned ht, htmask;
    int number_rule = 0;

    std::vector<Rule> rule;

    while (true) {
        Rule r;
        std::array<Point, 2> points{};
        if (fscanf(fp, "@%d.%d.%d.%d/%d\t%d.%d.%d.%d/%d\t%d : %d\t%d : %d\t%x/%x\t%x/%x\n",
                   &sip1, &sip2, &sip3, &sip4, &smask, &dip1, &dip2, &dip3, &dip4, &dmask, &sport1, &sport2,
                   &dport1, &dport2, &protocal, &protocol_mask, &ht, &htmask) != 18)
            break;

        r.prefix_length[0] = smask;
        r.prefix_length[1] = dmask;

        if (smask == 0) {
            points[0] = 0;
            points[1] = 0xFFFFFFFF;
        } else if (smask > 0 && smask <= 8) {
            tmp = sip1 << 24;
            points[0] = tmp;
            points[1] = points[0] + (1 << (32 - smask)) - 1;
        } else if (smask > 8 && smask <= 16) {
            tmp = sip1 << 24;
            tmp += sip2 << 16;
            points[0] = tmp;
            points[1] = points[0] + (1 << (32 - smask)) - 1;
        } else if (smask > 16 && smask <= 24) {
            tmp = sip1 << 24;
            tmp += sip2 << 16;
            tmp += sip3 << 8;
            points[0] = tmp;
            points[1] = points[0] + (1 << (32 - smask)) - 1;
        } else if (smask > 24 && smask <= 32) {
            tmp = sip1 << 24;
            tmp += sip2 << 16;
            tmp += sip3 << 8;
            tmp += sip4;
            points[0] = tmp;
            points[1] = points[0] + (1 << (32 - smask)) - 1;
        } else {
            printf("Src IP length exceeds 32\n");
            exit(-1);
        }
        r.range[0] = points;

        if (dmask == 0) {
            points[0] = 0;
            points[1] = 0xFFFFFFFF;
        } else if (dmask > 0 && dmask <= 8) {
            tmp = dip1 << 24;
            points[0] = tmp;
            points[1] = points[0] + (1 << (32 - dmask)) - 1;
        } else if (dmask > 8 && dmask <= 16) {
            tmp = dip1 << 24;
            tmp += dip2 << 16;
            points[0] = tmp;
            points[1] = points[0] + (1 << (32 - dmask)) - 1;
        } else if (dmask > 16 && dmask <= 24) {
            tmp = dip1 << 24;
            tmp += dip2 << 16;
            tmp += dip3 << 8;
            points[0] = tmp;
            points[1] = points[0] + (1 << (32 - dmask)) - 1;
        } else if (dmask > 24 && dmask <= 32) {
            tmp = dip1 << 24;
            tmp += dip2 << 16;
            tmp += dip3 << 8;
            tmp += dip4;
            points[0] = tmp;
            points[1] = points[0] + (1 << (32 - dmask)) - 1;
        } else {
            printf("Dest IP length exceeds 32\n");
            exit(-1);
        }
        r.range[1] = points;

        points[0] = sport1;
        points[1] = sport2;
        r.range[2] = points;

        points[0] = dport1;
        points[1] = dport2;
        r.range[3] = points;

        for (int i = 15; i >= 0; i--) {
            unsigned int Bit = 1 << i;
            unsigned sp = sport1 ^ sport2;
            if (sp & Bit) {
                break;
            }
            r.prefix_length[2]++;
        }

        for (int i = 15; i >= 0; i--) {
            unsigned int Bit = 1 << i;
            unsigned dp = dport1 ^ dport2;
            if (dp & Bit) {
                break;
            }
            r.prefix_length[3]++;
        }

        if (protocol_mask == 0xFF) {
            points[0] = protocal;
            points[1] = protocal;
        } else if (protocol_mask == 0) {
            points[0] = 0;
            points[1] = 0xFF;
        } else {
            printf("Protocol mask error\n");
            exit(-1);
        }
        r.range[4] = points;
        r.prefix_length[4] = protocol_mask;
        r.id = number_rule;

        rule.push_back(r);
        number_rule++;
    }

    int max_pri = number_rule - 1;
    for (int i = 0; i < number_rule; i++) {
        rule[i].priority = max_pri - i;
    }
    return rule;
}

std::vector<Packet> loadpacket(FILE *fp) {
    unsigned int header[MAXDIMENSIONS];
    unsigned int proto_mask, fid;
    int number_pkt = 0;
    std::vector<Packet> packets;
    while (true) {
        if (fscanf(fp, "%u %u %d %d %d %u %d\n", &header[0], &header[1], &header[2], &header[3], &header[4],
                   &proto_mask, &fid) == Null)
            break;
        Packet p;
        p.push_back(header[0]);
        p.push_back(header[1]);
        p.push_back(header[2]);
        p.push_back(header[3]);
        p.push_back(header[4]);
        p.push_back(fid);

        packets.push_back(p);
        number_pkt++;
    }

    return packets;
}

int main(int argc, char *argv[]) {
    for (int idx = 1; idx < argc; idx++) {
        if (strcmp(argv[idx], "-r") == 0) {
            const char *ruleFileName = argv[++idx];
            ruleName = ruleFileName;
            fpr = fopen(ruleFileName, "r");
        } else if (strcmp(argv[idx], "-b") == 0) {
            binth = atoi(argv[++idx]);
        } else if (strcmp(argv[idx], "-bit") == 0) {
            maxBits = atoi(argv[++idx]);
        } else if (strcmp(argv[idx], "-t") == 0) {
            maxTree = atoi(argv[++idx]);
        } else if (strcmp(argv[idx], "-l") == 0) {
            maxLevel = atoi(argv[++idx]);
        } else if (strcmp(argv[idx], "-p") == 0) {
            const char *packetFileName = argv[++idx];
            fpt = fopen(packetFileName, "r");
        } else if (strcmp(argv[idx], "-wrs") == 0) {
            wrsThreshold = atoi(argv[++idx]);
        // } else if (strcmp(argv[idx], "-debug") == 0) {  // 
//     DEBUG_MODE = true;
//     VERIFY_CLASSIFICATION = true;
        } else if (strcmp(argv[idx], "-h") == 0) {
            cout << "T2Tree" << endl;
            cout << "Usage: ./T2Tree_Project [-r ruleFile][-p traceFile][-b binth][-bit maxbit][-t maxTreenum][-l maxTreeDepth][-tss tssThreshold][-debug]" << endl;
            cout << "" << endl;
            cout << "Options:" << endl;
            cout << "  -r: rule set file path" << endl;
            cout << "  -p: packet trace file path" << endl;
            cout << "  -b: leaf node capacity (default: 8)" << endl;
            cout << "  -bit: max bits per level (default: 4)" << endl;
            cout << "  -wrs: WRS threshold (default: auto)" << endl;
            cout << "  -t: max number of trees (default: 32)" << endl;
            cout << "  -l: max tree depth (default: 10)" << endl;
            // cout << "  -debug: enable debug mode with verification" << endl;  
            cout << "  -h: show help" << endl;
            exit(-2);
        }
    }

    vector<Rule> rule;
    vector<Packet> packets;
    uint32_t number_rule = 0;

    std::chrono::time_point<std::chrono::steady_clock> start, end;
    std::chrono::duration<double> elapsed_seconds{};
    std::chrono::duration<double, std::milli> elapsed_milliseconds{};

    if (fpr != nullptr) {
        rule = loadrule(fpr);
        number_rule = static_cast<uint32_t>(rule.size());
        
        if (wrsThreshold == -1) {
            wrsThreshold = getRecommendedWRSThreshold(static_cast<int>(number_rule), binth);
        }

        //---T2Tree---Construction---
        printf("=== T2Tree Construction ===\n");
        printf("Parameters: maxBits=%d, maxLevel=%d, binth=%d, maxTree=%d, wrsThreshold=%d\n", 
               maxBits, maxLevel, binth, maxTree, wrsThreshold);
        printf("Rules loaded: %u\n\n", number_rule);
        
        printf("Construct T2Tree\n");
        start = std::chrono::steady_clock::now();
        T2Tree T2(maxBits, maxLevel, binth, maxTree, wrsThreshold);
        T2.ConstructClassifier(rule);
        end = std::chrono::steady_clock::now();
        elapsed_milliseconds = end - start;
        printf("\tConstruction time: %.3f ms\n", elapsed_milliseconds.count());
        printf("\tTotal Memory Size: %d(KB)\n", T2.MemSizeBytes() / 1024);
        printf("\tNumber of Trees: %zu\n", T2.NumTables());
        printf("\tAverage leaf depth: %.2f\n", T2.AverageLeafDepth());
        printf("\tAverage node balance: %.3f (1 = perfect)\n", T2.AverageNodeBalance());
        
        printf("\tOverflow Container Rules: %zu\n", T2.GetOverflowRuleCount());
        printf("\n");

        //---T2Tree---Classification---
        printf("Classify T2Tree\n");
        packets = loadpacket(fpt);
        uint32_t number_pkt = static_cast<uint32_t>(packets.size());
        const int trials = 10;
        printf("\tTotal packets (run %d times circularly): %lu\n", trials, static_cast<unsigned long>(packets.size() * trials));
        
        int match_miss = 0;
        vector<int> matchid(number_pkt, -1);
        std::chrono::duration<double> sum_timeT2(0);
        
        // //  Debug mode: detailed verification
        // if (VERIFY_CLASSIFICATION) {
        //     printf("\n=== Verification Mode Enabled ===\n");
        //     int errorCount = 0;
        //     const int maxErrorsToShow = 10;
        //     
        //     for (uint32_t j = 0; j < std::min(number_pkt, 1000u); j++) {  // Only verify first 1000
        //         int t2Priority = T2.ClassifyAPacket(packets[j]);
        //         int bruteForcePriority = bruteForceClassify(rule, packets[j]);
        //         
        //         if (t2Priority != bruteForcePriority) {
        //             errorCount++;
        //             if (errorCount <= maxErrorsToShow) {
        //                 printf("Error #%d: Packet %d - T2Tree returned %d, brute force returned %d\n",
        //                        errorCount, j, t2Priority, bruteForcePriority);
        //                 
        //                 // Find expected rule
        //                 int expectedRuleId = static_cast<int>(packets[j][5]);
        //                 if (expectedRuleId >= 0 && expectedRuleId < static_cast<int>(rule.size())) {
        //                     analyzeClassificationError(rule[expectedRuleId], t2Priority, rule, packets[j]);
        //                 }
        //             }
        //         }
        //     }
        //     
        //     if (errorCount > 0) {
        //         printf("Verification found %d classification errors (verified %d packets)\n", errorCount, std::min(number_pkt, 1000u));
        //         printf("Recommendations:\n");
        //         printf("1. Check if rules in WRS nodes are correctly sorted\n");
        //         printf("2. Verify priority pruning in inter-tree search is correct\n");
        //         printf("3. Check data structure consistency after update operations\n");
        //     } else {
        //         printf("Verification passed: First %d packets classified correctly\n", std::min(number_pkt, 1000u));
        //     }
        //     printf("===================\n\n");
        // }
        
        // Normal performance testing
        uint64_t totalMemoryAccess = 0;
        int worstCaseAccess = 0;
        
        for (int i = 0; i < trials; i++) {
            start = std::chrono::steady_clock::now();
            for (uint32_t j = 0; j < number_pkt; j++) {
                matchid[j] = static_cast<int>(number_rule) - 1 - T2.ClassifyAPacket(packets[j]);
            }
            end = std::chrono::steady_clock::now();
            elapsed_seconds = end - start;
            sum_timeT2 += elapsed_seconds;
            
            for (uint32_t j = 0; j < number_pkt; j++) {
                if (matchid[j] == -1 || static_cast<unsigned int>(matchid[j]) > packets[j][5]) {
                    match_miss++;
                    
                    //                     //  Debug mode: output misclassification details
//                     if (DEBUG_MODE && match_miss <= 10) {
//                         printf("Misclassification: Packet %d, returned rule ID=%d, expected rule ID=%d\n",
//                                j, matchid[j], static_cast<int>(packets[j][5]));
//                     }
                }
            }
        }
        
        // Get memory access statistics
        totalMemoryAccess = T2.MemoryAccess();
        worstCaseAccess = T2.WorstMemoryAccess();
        
        printf("\t%d packets are classified, %d of them are misclassified\n", 
               static_cast<int>(number_pkt * trials), match_miss);
        printf("\tTotal classification time: %.6f s\n", sum_timeT2.count() / trials);
        printf("\tAverage classification time: %.6f us\n", sum_timeT2.count() * 1e6 / (trials * packets.size()));
        printf("\tThroughput: %.6f Mpps\n", 1 / (sum_timeT2.count() * 1e6 / (trials * packets.size())));
        
        // memory access count statistics output
        // printf("\n=== Memory Access Statistics ===\n");
        // printf("\tTotal memory accesses: %lu\n", totalMemoryAccess);
        // printf("\tWorst case memory accesses: %d\n", worstCaseAccess);
        // 
        // if (number_pkt * trials > 0) {
        //     double avgMemoryAccess = static_cast<double>(totalMemoryAccess) / (number_pkt * trials);
        //     printf("\tAverage memory accesses per packet: %.2f\n", avgMemoryAccess);
        // }
        // 
        // // Calculate memory access efficiency
        // if (totalMemoryAccess > 0) {
        //     double memoryEfficiency = (static_cast<double>(number_pkt * trials) / totalMemoryAccess) * 100;
        //     printf("\tMemory access efficiency: %.2f%% (packets per access)\n", memoryEfficiency);
        // }
        // printf("================================\n\n");

        //---Update Test---
        printf("Update T2Tree\n");
        
        uint32_t number_update = number_rule < MAXRULES ? number_rule : MAXRULES;
        printf("\tThe number of updated rules = %u\n", number_update);
        
        srand(static_cast<unsigned>(time(nullptr)));
        for (int &ra : rand_update) {
            ra = rand() % 2;
        }
        
        std::vector<int> operations(number_update);
        for (uint32_t i = 0; i < number_update; i++) {
            operations[i] = rand_update[i];
        }
        
        std::vector<Rule> updateRules(rule.begin(), rule.begin() + number_update);

        start = std::chrono::steady_clock::now();
        UpdateStatistics updateStats = T2.performStableUpdate(updateRules, operations);
        end = std::chrono::steady_clock::now();
        elapsed_seconds = end - start;
        
        printf("\t%u rules update: insert_num = %u delete_num = %u\n",
               updateStats.insertAttempts + updateStats.deleteAttempts, 
               updateStats.insertSuccesses, 
               updateStats.deleteSuccesses);
        printf("\tTotal update time: %.6f s\n", elapsed_seconds.count());
        printf("\tAverage update time: %.6f us\n", elapsed_seconds.count() * 1e6 / number_update);
        printf("\tThroughput: %.6f Mpps\n", 1 / (elapsed_seconds.count() * 1e6 / number_update));
        
        // // Debug mode: verify again after update
        // if (VERIFY_CLASSIFICATION) {
        //     printf("\n=== Post-Update Verification ===\n");
        //     int postUpdateErrors = 0;
        //     for (uint32_t j = 0; j < std::min(number_pkt, 100u); j++) {
        //         int t2Priority = T2.ClassifyAPacket(packets[j]);
        //         // Note: brute force search after update needs to use the updated rule set
        //         // Simplified here, only check if valid priority is returned
        //         if (t2Priority < -1) {
        //             postUpdateErrors++;
        //             printf("Post-update error: Packet %d returned invalid priority %d\n", j, t2Priority);
        //         }
        //     }
        //     if (postUpdateErrors > 0) {
        //         printf("Found %d errors after update\n", postUpdateErrors);
        //     } else {
        //         printf("Post-update verification passed\n");
        //     }
        //     printf("===================\n");
        // }
        
    } else {
        printf("Cannot open rule file. Please check the file path.\n");
        printf("Use -h for help.\n");
    }
    
    if (fpr) fclose(fpr);
    if (fpt) fclose(fpt);
    
    return 0;
}