#ifndef T2_TREE_H
#define T2_TREE_H

#include "../ElementaryClasses.h"
#include "WildcardRuleStorage.h"
#include <vector>
#include <queue>
#include <memory>
#include <map>
#include <climits>
#include <utility>
#include <chrono>
#include <string>
#include <unordered_map>
#include <unordered_set>

struct T2TreeNode {
    std::vector<Rule> classifier;
    int nrules;
    int depth;
    bool isLeaf;
    std::vector<int> opt, bit;
    
    bool hasWRS;
    std::unique_ptr<WildcardRuleStorage> wrsNode;
    int maxWRSPriority;
    
    std::vector<T2TreeNode*> children;
    T2TreeNode* parent;
    std::vector<int> left;
    
    bool isOverflowTree;  // Not used
    int maxLeafPriority;

    T2TreeNode(const std::vector<Rule>& rules, int level = 0, bool isleaf = false) 
        : nrules(static_cast<int>(rules.size())), depth(level), 
          isLeaf(isleaf), hasWRS(false), wrsNode(nullptr), maxWRSPriority(-1), 
          parent(nullptr), isOverflowTree(false), maxLeafPriority(-1) {
        left = {0, 0, 0, 0, 0};
        
        classifier = rules;
        if (!classifier.empty()) {
            std::sort(classifier.begin(), classifier.end(), 
                [](const Rule& a, const Rule& b) {
                    return a.priority > b.priority;
                });
            if (isLeaf) {
                maxLeafPriority = classifier[0].priority;
            }
        }
    }
    
    ~T2TreeNode() {
        for (auto child : children) {
            delete child;
        }
    }
    
    void createWRSIfBeneficial(int wildcardCount, int capacity = 8) {
        if (!hasWRS && wildcardCount >= capacity && depth >= 2 && depth <= 6) {
            wrsNode = std::make_unique<WildcardRuleStorage>(capacity);
            hasWRS = true;
            maxWRSPriority = -1;
        }
    }
    
    void createWRSForOverflow(int capacity) {
        if (!hasWRS) {
            wrsNode = std::make_unique<WildcardRuleStorage>(capacity);
            hasWRS = true;
            maxWRSPriority = -1;
        }
    }
    
    void updateWRSMaxPriority() {
        if (hasWRS && wrsNode) {
            if (wrsNode->size() == 0) {
                maxWRSPriority = -1;
            } else {
                wrsNode->ensureSorted();
                const auto& rules = wrsNode->getRules();
                if (!rules.empty()) {
                    maxWRSPriority = rules[0].priority;
                } else {
                    maxWRSPriority = -1;
                }
            }
        } else {
            maxWRSPriority = -1;
        }
    }
    
    void updateMaxLeafPriority() {
        if (isLeaf && !classifier.empty()) {
            maxLeafPriority = classifier[0].priority;
        } else {
            maxLeafPriority = -1;
        }
    }
    
    int getDepth() const {
        if (isLeaf) return depth;
        int maxChildDepth = depth;
        for (auto child : children) {
            if (child) {
                maxChildDepth = std::max(maxChildDepth, child->getDepth());
            }
        }
        return maxChildDepth;
    }
};

struct UpdateStatistics {
    uint32_t insertAttempts = 0;
    uint32_t insertSuccesses = 0;
    uint32_t deleteAttempts = 0;
    uint32_t deleteSuccesses = 0;
    
    void printSummary() const {
        printf("\tInsert success rate: %u/%u (%.1f%%)\n", 
               insertSuccesses, insertAttempts, 
               insertAttempts > 0 ? (100.0 * insertSuccesses / insertAttempts) : 0.0);
        printf("\tDelete success rate: %u/%u (%.1f%%)\n", 
               deleteSuccesses, deleteAttempts,
               deleteAttempts > 0 ? (100.0 * deleteSuccesses / deleteAttempts) : 0.0);
        printf("\tTotal updates: %u rules update: insert_num = %u delete_num = %u\n",
               insertAttempts + deleteAttempts, insertSuccesses, deleteSuccesses);
    }
};

// Overflow container
class HybridOverflowContainer {
private:
    struct PriorityLayer {
        int minPriority;
        int maxPriority;
        std::vector<Rule> rules;
        bool sorted = false;
        
        PriorityLayer(int min = 0, int max = 0) 
            : minPriority(min), maxPriority(max), sorted(false) {}
    };
    
    std::vector<PriorityLayer> layers;
    std::unordered_map<int, size_t> ruleIdToLayer;
    static constexpr int LAYER_SIZE = 10000;
    
public:
    void insert(const Rule& rule);
    bool remove(int rule_id);
    int search(const Packet& packet, int currentBest = -1) const;
    size_t size() const;
    void clear();
    Memory memoryUsage() const;
    void optimize();
    int getMaxPriority() const;  // Get maximum priority
};

enum RuleType {
    SPECIFIC_RULE,
    WILDCARD_RULE
};

class T2Tree : public PacketClassifier {
public:
    explicit T2Tree(int maxBits = 2, int maxLevel = 4, int binth = 10, int maxTreeNum = 32, int wrsThreshold = 10);
    ~T2Tree() override;
    
    void ConstructClassifier(const std::vector<Rule>& rules) override;
    int ClassifyAPacket(const Packet& packet) override;
    
    void DeleteRule(const Rule& delete_rule) override;
    void InsertRule(const Rule& insert_rule) override;
    
    Memory MemSizeBytes() const override;
    size_t NumTables() const override;
    size_t RulesInTable(size_t tableIndex) const override { 
        (void)tableIndex;
        return 0; 
    }

    double AverageLeafDepth() const;
    double AverageNodeBalance() const;
    
    size_t GetOverflowRuleCount() const;

    std::vector<int> GetSelectBit(T2TreeNode* node, std::vector<int>& opt);
    int CalculateLocation(const Rule& rule, const std::vector<int>& opt, const std::vector<int>& bit);
    inline int CalculatePacketLocation(const Packet& p, const std::vector<int>& opt, const std::vector<int>& bit);
    
    bool DeleteRuleSimple(const Rule& delete_rule);
    bool InsertRuleConservative(const Rule& insert_rule);

    UpdateStatistics performStableUpdate(const std::vector<Rule>& rules, const std::vector<int>& operations);
    UpdateStatistics performBatchUpdate(const std::vector<Rule>& rules, const std::vector<int>& operations);

private:
    std::vector<Rule> classifier;
    std::vector<T2TreeNode*> roots;
    
    int maxBits;
    int maxLevel;
    int binth;
    int maxTreeNum;
    int wrsThreshold;
    std::vector<std::vector<int>> partitionOpt;
    std::vector<int> Maxpri;
    
    uint64_t Query;
    
    std::vector<std::pair<int, size_t>> treeSearchOrder;
    
    // Overflow management
    int normalTreeCount;
    HybridOverflowContainer hybridOverflowContainer;
    int overflowMaxPriority = -1;  // Record maximum priority of overflow container
    
    // Rule index
    std::vector<int8_t> ruleTreeIndex;
    int maxRuleId;
    
    // Update buffer
    struct UpdateBuffer {
        std::vector<Rule> recentInserts;
        std::unordered_set<int> pendingDeletes;
        int lastSuccessfulTree = 0;
        
        void clear() {
            if (recentInserts.size() > 1000) {
                recentInserts.erase(recentInserts.begin(), 
                                   recentInserts.begin() + recentInserts.size() - 100);
            }
            pendingDeletes.clear();
        }
    } updateBuffer;
    
    // Core functions
    T2TreeNode* CreateSubT2TreeBalancedOptimized(const std::vector<Rule>& rules, 
                                                 std::vector<Rule>& kickedRules, 
                                                 int treeIndex);
    void ProcessWildcardRulesBalanced(T2TreeNode* node, 
                                     const std::vector<Rule>& wildcardRules,
                                     std::vector<Rule>& kickedRules,
                                     int balancedWRSThreshold);
    
    void performBalancedTreeMerging();
    int countTreeRules(T2TreeNode* root) const;
    void extractAllRulesFromTree(T2TreeNode* root, std::vector<Rule>& rules);
    
    void buildTreeSearchOrder();
    int SearchUltraFastTwoPhase(T2TreeNode* root, const Packet& p, int currentBest);
    int searchLeafComplete(T2TreeNode* leafNode, const Packet& p, int currentBest = -1);
    
    // Update functions
    bool InsertRuleOptimized(const Rule& insert_rule);
    bool DeleteRuleOptimized(const Rule& delete_rule);
    RuleType classifyRule(const Rule& rule) const;
    bool insertToShallowTree(const Rule& rule);
    bool insertToOverflowDirect(const Rule& rule);
    bool tryFastInsert(T2TreeNode* root, const Rule& rule);
    bool deleteFromKnownLocation(const Rule& rule, int treeIdx);
    bool batchDelete(const std::vector<Rule>& rules);
    void processPendingDeletes();
    int getTreeDepth(T2TreeNode* root) const;
    
    // Compatibility functions
    bool InsertRuleStable(const Rule& insert_rule);
    bool DeleteRuleStable(const Rule& delete_rule);
    bool tryStableInsert(T2TreeNode* root, const Rule& insert_rule);
    bool tryStableDelete(T2TreeNode* root, const Rule& delete_rule);
    
    bool InsertRuleCompatible(const Rule& insert_rule);
    bool DeleteRuleCompatible(const Rule& delete_rule);
    bool tryCompatibleInsert(T2TreeNode* root, const Rule& insert_rule);
    bool tryCompatibleDelete(T2TreeNode* root, const Rule& delete_rule);
    int recalculateTreeMaxPriority(T2TreeNode* root);
    
    bool hasWildcardInSelectedBits(const Rule& rule, const std::vector<int>& opt, const std::vector<int>& bit);
    int getBalancedAggressiveLeafCapacity(int remainingRules, int treeIndex);
    int countRuleWildcards(const Rule& rule) const;
};

#endif // T2_TREE_H