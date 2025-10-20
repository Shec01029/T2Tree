#include "T2Tree.h"
#include <set>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <unordered_map>

// Add auxiliary function to calculate rule access count based on cache line
inline int CalculateRuleAccess(int numRules) {
    // Based on cache line (64 bytes, about 8 rules)
    if (numRules == 0) return 0;
    return 1 + (numRules - 1) / 8;
}

// ========== HybridOverflowContainer Implementation ==========
void HybridOverflowContainer::insert(const Rule& rule) {
    int layerIdx = rule.priority / LAYER_SIZE;
    
    if (layerIdx >= static_cast<int>(layers.size())) {
        layers.resize(layerIdx + 1, 
            PriorityLayer(layerIdx * LAYER_SIZE, (layerIdx + 1) * LAYER_SIZE - 1));
    }
    
    layers[layerIdx].rules.push_back(rule);
    layers[layerIdx].maxPriority = std::max(layers[layerIdx].maxPriority, rule.priority);
    layers[layerIdx].sorted = false;
    
    ruleIdToLayer[rule.id] = layerIdx;
}

bool HybridOverflowContainer::remove(int rule_id) {
    auto it = ruleIdToLayer.find(rule_id);
    if (it == ruleIdToLayer.end()) {
        return false;
    }
    
    size_t layerIdx = it->second;
    if (layerIdx >= layers.size()) {
        return false;
    }
    
    auto& layer = layers[layerIdx];
    auto ruleIt = std::find_if(layer.rules.begin(), layer.rules.end(),
        [rule_id](const Rule& r) { return r.id == rule_id; });
    
    if (ruleIt != layer.rules.end()) {
        layer.rules.erase(ruleIt);
        layer.sorted = false;
        
        if (layer.rules.empty()) {
            layer.maxPriority = -1;
        } else {
            layer.maxPriority = std::max_element(layer.rules.begin(), layer.rules.end(),
                [](const Rule& a, const Rule& b) { return a.priority < b.priority; })->priority;
        }
        
        ruleIdToLayer.erase(it);
        return true;
    }
    
    return false;
}

int HybridOverflowContainer::search(const Packet& packet, int currentBest) const {
    int bestPriority = currentBest;
    
    // Search from high priority layers to low priority layers
    for (int i = static_cast<int>(layers.size()) - 1; i >= 0; i--) {
        const auto& layer = layers[i];
        
        // Layer pruning
        if (layer.rules.empty() || layer.maxPriority <= bestPriority) {
            continue;
        }
        
        // Ensure layer is sorted
        if (!layer.sorted) {
            auto& mutableLayer = const_cast<PriorityLayer&>(layer);
            std::sort(mutableLayer.rules.begin(), mutableLayer.rules.end(),
                [](const Rule& a, const Rule& b) { return a.priority > b.priority; });
            mutableLayer.sorted = true;
        }
        
        // Search rules within layer (rules are sorted by priority in descending order)
        for (const auto& rule : layer.rules) {
            if (rule.priority <= bestPriority) {
                break;  // Subsequent rules have lower priority
            }
            
            if (rule.MatchesPacket(packet)) {
                bestPriority = rule.priority;
                break;  // Found the highest priority match in this layer
            }
        }
    }
    
    return bestPriority;
}

size_t HybridOverflowContainer::size() const {
    size_t total = 0;
    for (const auto& layer : layers) {
        total += layer.rules.size();
    }
    return total;
}

void HybridOverflowContainer::clear() {
    layers.clear();
    ruleIdToLayer.clear();
}

Memory HybridOverflowContainer::memoryUsage() const {
    Memory mem = 0;
    
    for (const auto& layer : layers) {
        mem += static_cast<Memory>(layer.rules.size() * sizeof(Rule));
        mem += sizeof(PriorityLayer);
    }
    
    mem += static_cast<Memory>(ruleIdToLayer.size() * (sizeof(int) + sizeof(size_t)));
    
    return mem;
}

void HybridOverflowContainer::optimize() {
    std::vector<Rule> allRules;
    
    for (auto& layer : layers) {
        allRules.insert(allRules.end(), layer.rules.begin(), layer.rules.end());
    }
    
    if (allRules.empty()) return;
    
    std::sort(allRules.begin(), allRules.end(),
        [](const Rule& a, const Rule& b) { return a.priority > b.priority; });
    
    // Re-layer
    int numLayers = std::min(10, std::max(1, static_cast<int>(allRules.size()) / 100));
    int rulesPerLayer = static_cast<int>(allRules.size()) / numLayers;
    
    layers.clear();
    ruleIdToLayer.clear();
    
    for (size_t i = 0; i < allRules.size(); i++) {
        int layerIdx = std::min(static_cast<int>(i / rulesPerLayer), numLayers - 1);
        
        if (layerIdx >= static_cast<int>(layers.size())) {
            layers.emplace_back();
        }
        
        layers[layerIdx].rules.push_back(allRules[i]);
        layers[layerIdx].maxPriority = std::max(layers[layerIdx].maxPriority, allRules[i].priority);
        layers[layerIdx].minPriority = std::min(layers[layerIdx].minPriority, allRules[i].priority);
        layers[layerIdx].sorted = true;
        
        ruleIdToLayer[allRules[i].id] = layerIdx;
    }
}

int HybridOverflowContainer::getMaxPriority() const {
    int maxPri = -1;
    for (const auto& layer : layers) {
        if (!layer.rules.empty()) {
            maxPri = std::max(maxPri, layer.maxPriority);
        }
    }
    return maxPri;
}

// ========== T2Tree Constructor and Destructor ==========
T2Tree::T2Tree(int maxBits, int maxLevel, int binth, int maxTreeNum, int wrsThreshold) 
    : normalTreeCount(0), maxRuleId(0), overflowMaxPriority(-1) {
    this->maxBits = maxBits;
    this->maxLevel = maxLevel;
    this->binth = binth;
    this->maxTreeNum = maxTreeNum;
    this->wrsThreshold = wrsThreshold;
    this->Query = 0;

    partitionOpt.resize(6);
    for (int i = -1; i < 5; i++) {
        partitionOpt[i + 1].push_back(i);
    }

    while (static_cast<int>(partitionOpt[0].size()) < maxBits) {
        auto temp = partitionOpt;
        partitionOpt.clear();
        for (auto iter : temp) {
            for (int i = iter.back(); i < 5; i++) {
                std::vector<int> tmp = iter;
                tmp.push_back(i);
                partitionOpt.push_back(tmp);
            }
        }
    }
}

T2Tree::~T2Tree() {
    // Only delete normal trees
    for (int i = 0; i < normalTreeCount; i++) {
        delete roots[i];
    }
}

// ========== Build Classifier ==========
void T2Tree::ConstructClassifier(const std::vector<Rule>& rules) {
    this->classifier = rules;
    std::vector<Rule> currRules = rules;
    std::vector<Rule> kickedRules;
    
    size_t initialRuleCount = rules.size();
    
    // Pre-allocate index space
    maxRuleId = 0;
    for (const auto& rule : rules) {
        maxRuleId = std::max(maxRuleId, rule.id);
    }
    ruleTreeIndex.resize(maxRuleId + 1, -1);
    
    // Sort rules
    std::sort(currRules.begin(), currRules.end(), 
        [](const Rule& a, const Rule& b) {
            return a.priority > b.priority;
        });
    
    // Build normal trees
    while (!currRules.empty() && static_cast<int>(roots.size()) < maxTreeNum - 1) {
        if (static_cast<int>(roots.size()) >= maxTreeNum / 2 && 
            currRules.size() <= static_cast<size_t>(binth * 3)) {
            break;
        }
        
        kickedRules.clear();
        Maxpri.push_back(-1);

        int currentTreeIndex = static_cast<int>(roots.size());
        int dynamicBinth = getBalancedAggressiveLeafCapacity(static_cast<int>(currRules.size()), currentTreeIndex);
        
        int originalBinth = this->binth;
        this->binth = dynamicBinth;
        
        T2TreeNode* node = CreateSubT2TreeBalancedOptimized(currRules, kickedRules, currentTreeIndex);
        roots.push_back(node);
        
        // Fix: Recalculate the actual maximum priority of this tree
        Maxpri.back() = recalculateTreeMaxPriority(node);
        
        // Record rule positions
        for (const auto& rule : currRules) {
            bool isKicked = std::find_if(kickedRules.begin(), kickedRules.end(),
                [&rule](const Rule& r) { return r.id == rule.id; }) != kickedRules.end();
            if (!isKicked && rule.id <= maxRuleId) {
                ruleTreeIndex[rule.id] = currentTreeIndex;
            }
        }
        
        this->binth = originalBinth;
        currRules = kickedRules;
        SortRules(currRules);
    }
    
    normalTreeCount = static_cast<int>(roots.size());
    
    // All remaining rules go to overflow container
    if (!currRules.empty()) {
        hybridOverflowContainer.clear();  // Ensure clean state
        
        // First sort rules to ensure correct priority
        std::sort(currRules.begin(), currRules.end(),
            [](const Rule& a, const Rule& b) { return a.priority > b.priority; });
        
        for (const auto& rule : currRules) {
            hybridOverflowContainer.insert(rule);
            if (rule.id <= maxRuleId) {
                ruleTreeIndex[rule.id] = 127;  // 127 indicates overflow
            }
        }
        
        // Fix: Record maximum priority of overflow container
        overflowMaxPriority = hybridOverflowContainer.getMaxPriority();
    }
    
    // Verify rule count
    size_t totalRules = 0;
    for (int i = 0; i < normalTreeCount; i++) {
        totalRules += countTreeRules(roots[i]);
    }
    totalRules += hybridOverflowContainer.size();
    
    if (totalRules != initialRuleCount) {
        printf("Warning: Rule count mismatch! Initial:%zu, After construction:%zu\n", 
               initialRuleCount, totalRules);
    }
    
    if (normalTreeCount > 3) {
        performBalancedTreeMerging();
    }
    
    buildTreeSearchOrder();
    
    if (hybridOverflowContainer.size() > 1000) {
        hybridOverflowContainer.optimize();
        overflowMaxPriority = hybridOverflowContainer.getMaxPriority();  // Update maximum priority
    }
}

// ========== Packet Classification ==========
int T2Tree::ClassifyAPacket(const Packet& packet) {
    int globalBestPriority = -1;
    Query = 0;  // Reset query counter
    
    // Optimize search strategy
    bool searchedOverflow = false;
    if (hybridOverflowContainer.size() > 0 && overflowMaxPriority > 80000) {
        // Overflow container access: 1 time + cache line based rule access
        Query++;  
        int numOverflowRules = static_cast<int>(hybridOverflowContainer.size());
        // Query += CalculateRuleAccess(numOverflowRules);
        
        int overflowResult = hybridOverflowContainer.search(packet, globalBestPriority);
        if (overflowResult > globalBestPriority) {
            globalBestPriority = overflowResult;
        }
        searchedOverflow = true;
    }
    
    // Search normal trees
    for (const auto& treePair : treeSearchOrder) {
        size_t i = treePair.second;
        int maxPri = treePair.first;
        
        // Only process normal trees
        if (i >= static_cast<size_t>(normalTreeCount)) {
            continue;
        }
        
        // Use more conservative pruning
        if (globalBestPriority >= maxPri && globalBestPriority - maxPri > 500) {
            continue;
        }
        
        Query++;  // Access tree root
        int treeResult = SearchUltraFastTwoPhase(roots[i], packet, globalBestPriority);
        if (treeResult > globalBestPriority) {
            globalBestPriority = treeResult;
        }
    }
    
    // Search overflow container if not searched before
    if (!searchedOverflow && hybridOverflowContainer.size() > 0) {
        Query++;  
        int numOverflowRules = static_cast<int>(hybridOverflowContainer.size());
        // Query += CalculateRuleAccess(numOverflowRules);
        
        int overflowResult = hybridOverflowContainer.search(packet, globalBestPriority);
        if (overflowResult > globalBestPriority) {
            globalBestPriority = overflowResult;
        }
    }
    
    QueryUpdate(Query);  // Update statistics
    return globalBestPriority;
}

// ========== Auxiliary Functions ==========
int T2Tree::countRuleWildcards(const Rule& rule) const {
    int wildcards = 0;
    
    for (int i = 0; i < 5; i++) {
        if (rule.prefix_length[i] == 0) {
            wildcards++;
        }
        // Port range check
        if (i == 2 || i == 3) {
            if (rule.range[i][HighDim] - rule.range[i][LowDim] > 1000) {
                wildcards++;
            }
        }
    }
    
    return wildcards;
}

RuleType T2Tree::classifyRule(const Rule& rule) const {
    int wildcards = countRuleWildcards(rule);
    return (wildcards >= 2) ? WILDCARD_RULE : SPECIFIC_RULE;
}

void T2Tree::buildTreeSearchOrder() {
    treeSearchOrder.clear();
    // Only include normal trees
    for (int i = 0; i < normalTreeCount; i++) {
        if (i < static_cast<int>(Maxpri.size())) {
            treeSearchOrder.push_back({Maxpri[i], i});
        }
    }
    std::sort(treeSearchOrder.begin(), treeSearchOrder.end(), 
              std::greater<std::pair<int, size_t>>());
}

size_t T2Tree::GetOverflowRuleCount() const {
    return hybridOverflowContainer.size();
}

Memory T2Tree::MemSizeBytes() const {
    int nNodeCount = 0, nRuleCount = 0, nPTRCount = 0, nWRSCount = 0;
    Memory totMemory = 0;
    
    for (int i = 0; i < normalTreeCount; i++) {
        std::queue<T2TreeNode*> que;
        que.push(roots[i]);
        while (!que.empty()) {
            T2TreeNode* node = que.front();
            que.pop();
            nNodeCount++;
            
            if (node->hasWRS && node->wrsNode) {
                nWRSCount++;
                nRuleCount += static_cast<int>(node->wrsNode->size());
            }
            
            if (node->isLeaf) {
                nRuleCount += node->nrules;
                continue;
            }
            
            nPTRCount += static_cast<int>(node->children.size());
            for (auto iter : node->children) {
                if (iter) {
                    que.push(iter);
                }
            }
        }
    }
    
    totMemory = nNodeCount * NODE_SIZE + nRuleCount * PTR_SIZE + nPTRCount * PTR_SIZE + nWRSCount * TREE_NODE_SIZE;
    totMemory += static_cast<Memory>(ruleTreeIndex.size() * sizeof(int8_t));
    totMemory += hybridOverflowContainer.memoryUsage();
    
    return totMemory;
}

size_t T2Tree::NumTables() const {
    return normalTreeCount + (hybridOverflowContainer.size() > 0 ? 1 : 0);
}

// ========== Search Functions (Fair Memory Access Counting) ==========
int T2Tree::SearchUltraFastTwoPhase(T2TreeNode* root, const Packet& p, int currentBest) {
    if (!root) return -1;
    
    constexpr int MAX_DEPTH = 32;
    struct FastPathNode {
        T2TreeNode* node;
        bool checkWRS;
        int wrsPri;
    };
    
    FastPathNode pathStack[MAX_DEPTH];
    int pathDepth = 0;
    
    T2TreeNode* current = root;
    int bestPriority = -1;
    
    // Phase 1: Traverse to leaf node
    while (current && !current->isLeaf && pathDepth < MAX_DEPTH - 1) {
        bool shouldCheck = current->hasWRS && current->wrsNode && 
                          current->wrsNode->size() > 0 &&
                          current->maxWRSPriority > currentBest;
        
        pathStack[pathDepth++] = {current, shouldCheck, current->maxWRSPriority};
        
        int loc = CalculatePacketLocation(p, current->opt, current->bit);
        Query++;  // 🔥 Internal node access: 1 time
        
        if (loc < static_cast<int>(current->children.size()) && current->children[loc]) {
            current = current->children[loc];
        } else {
            break;
        }
    }
    
    // Search leaf node
    if (current && current->isLeaf) {
        bestPriority = searchLeafComplete(current, p, currentBest);
    }
    
    // Phase 2: Search WRS when necessary
    for (int i = pathDepth - 1; i >= 0; i--) {
        if (pathStack[i].checkWRS && pathStack[i].wrsPri > bestPriority) {
            Query++;  // 🔥 WRS access: 1 time (hash lookup)
            int wrsResult = pathStack[i].node->wrsNode->searchHighestPriority(p);
            if (wrsResult > bestPriority) {
                bestPriority = wrsResult;
            }
        }
    }
    
    return bestPriority;
}

int T2Tree::searchLeafComplete(T2TreeNode* leafNode, const Packet& p, int currentBest) {
    if (!leafNode || leafNode->classifier.empty()) {
        return -1;
    }
    
    // Early pruning
    if (leafNode->maxLeafPriority >= 0 && leafNode->maxLeafPriority <= currentBest) {
        return -1;
    }
    
    const auto& rules = leafNode->classifier;
    int numRules = static_cast<int>(rules.size());
    
    // Cache line based memory access counting
    // Query += CalculateRuleAccess(numRules);
    
    // Rules are sorted in descending priority order, find the first match
    for (const Rule& rule : rules) {
        if (rule.priority <= currentBest) {
            return -1;  // Subsequent rules have lower priority
        }
        
        if (rule.MatchesPacket(p)) {
            return rule.priority;  // Found the highest priority match
        }
    }
    
    return -1;
}

int T2Tree::recalculateTreeMaxPriority(T2TreeNode* root) {
    if (!root) return -1;
    
    int maxPri = -1;
    std::queue<T2TreeNode*> que;
    que.push(root);
    
    while (!que.empty()) {
        T2TreeNode* node = que.front();
        que.pop();
        
        if (node->isLeaf && !node->classifier.empty()) {
            maxPri = std::max(maxPri, node->classifier[0].priority);
        }
        
        if (node->hasWRS && node->wrsNode && node->wrsNode->size() > 0) {
            const auto& wrsRules = node->wrsNode->getRules();
            if (!wrsRules.empty()) {
                maxPri = std::max(maxPri, wrsRules[0].priority);
            }
        }
        
        for (auto child : node->children) {
            if (child) {
                que.push(child);
            }
        }
    }
    
    return maxPri;
}

int T2Tree::getTreeDepth(T2TreeNode* root) const {
    if (!root) return 0;
    return root->getDepth();
}

int T2Tree::countTreeRules(T2TreeNode* root) const {
    if (!root) return 0;
    
    int count = 0;
    std::queue<T2TreeNode*> que;
    que.push(root);
    
    while (!que.empty()) {
        T2TreeNode* node = que.front();
        que.pop();
        
        if (node->isLeaf) {
            count += node->nrules;
        }
        
        if (node->hasWRS && node->wrsNode) {
            count += static_cast<int>(node->wrsNode->size());
        }
        
        for (auto child : node->children) {
            if (child) {
                que.push(child);
            }
        }
    }
    
    return count;
}

void T2Tree::extractAllRulesFromTree(T2TreeNode* root, std::vector<Rule>& rules) {
    if (!root) return;
    
    std::queue<T2TreeNode*> que;
    que.push(root);
    
    while (!que.empty()) {
        T2TreeNode* node = que.front();
        que.pop();
        
        if (node->isLeaf) {
            rules.insert(rules.end(), node->classifier.begin(), node->classifier.end());
        }
        
        if (node->hasWRS && node->wrsNode) {
            const auto& wrsRules = node->wrsNode->getRules();
            rules.insert(rules.end(), wrsRules.begin(), wrsRules.end());
        }
        
        for (auto child : node->children) {
            if (child) {
                que.push(child);
            }
        }
    }
}

// ========== Update Functions ==========
void T2Tree::InsertRule(const Rule& insert_rule) {
    InsertRuleOptimized(insert_rule);
}

void T2Tree::DeleteRule(const Rule& delete_rule) {
    DeleteRuleOptimized(delete_rule);
}

bool T2Tree::InsertRuleOptimized(const Rule& insert_rule) {
    RuleType type = classifyRule(insert_rule);
    
    if (type == SPECIFIC_RULE) {
        return insertToShallowTree(insert_rule);
    } else {
        return insertToOverflowDirect(insert_rule);
    }
}

bool T2Tree::DeleteRuleOptimized(const Rule& delete_rule) {
    // Check recently inserted rules
    auto it = std::find_if(updateBuffer.recentInserts.begin(), 
                           updateBuffer.recentInserts.end(),
                           [&](const Rule& r) { return r.id == delete_rule.id; });
    
    if (it != updateBuffer.recentInserts.end()) {
        updateBuffer.recentInserts.erase(it);
        if (delete_rule.id <= maxRuleId && ruleTreeIndex[delete_rule.id] >= 0) {
            return deleteFromKnownLocation(delete_rule, ruleTreeIndex[delete_rule.id]);
        }
    }
    
    // Use index to locate
    if (delete_rule.id <= maxRuleId && ruleTreeIndex[delete_rule.id] >= 0) {
        int treeIdx = ruleTreeIndex[delete_rule.id];
        
        if (treeIdx == 127) {
            // Delete from overflow container
            bool success = hybridOverflowContainer.remove(delete_rule.id);
            if (success) {
                ruleTreeIndex[delete_rule.id] = -1;
                // Update overflow container maximum priority
                overflowMaxPriority = hybridOverflowContainer.getMaxPriority();
            }
            return success;
        } else if (treeIdx < normalTreeCount) {
            return deleteFromKnownLocation(delete_rule, treeIdx);
        }
    }
    
    // Deferred deletion
    updateBuffer.pendingDeletes.insert(delete_rule.id);
    if (updateBuffer.pendingDeletes.size() >= 50) {
        processPendingDeletes();
    }
    
    return true;
}

bool T2Tree::insertToShallowTree(const Rule& rule) {
    // Try recently successful tree first
    if (updateBuffer.lastSuccessfulTree < normalTreeCount) {
        if (tryFastInsert(roots[updateBuffer.lastSuccessfulTree], rule)) {
            if (rule.id <= maxRuleId) {
                ruleTreeIndex[rule.id] = updateBuffer.lastSuccessfulTree;
            }
            updateBuffer.recentInserts.push_back(rule);
            // Update Maxpri
            Maxpri[updateBuffer.lastSuccessfulTree] = recalculateTreeMaxPriority(roots[updateBuffer.lastSuccessfulTree]);
            buildTreeSearchOrder();  // Rebuild search order
            return true;
        }
    }
    
    // Find tree with minimum depth
    int minDepth = INT_MAX;
    int bestIndex = -1;
    
    for (int i = 0; i < normalTreeCount; i++) {
        if (i == updateBuffer.lastSuccessfulTree) continue;
        
        int depth = getTreeDepth(roots[i]);
        if (depth < minDepth) {
            minDepth = depth;
            bestIndex = i;
        }
    }
    
    if (bestIndex >= 0 && tryFastInsert(roots[bestIndex], rule)) {
        if (rule.id <= maxRuleId) {
            ruleTreeIndex[rule.id] = bestIndex;
        }
        updateBuffer.recentInserts.push_back(rule);
        updateBuffer.lastSuccessfulTree = bestIndex;
        // Update Maxpri
        Maxpri[bestIndex] = recalculateTreeMaxPriority(roots[bestIndex]);
        buildTreeSearchOrder();  // Rebuild search order
        return true;
    }
    
    // If failed, add to overflow container
    return insertToOverflowDirect(rule);
}

bool T2Tree::insertToOverflowDirect(const Rule& rule) {
    hybridOverflowContainer.insert(rule);
    
    if (rule.id <= maxRuleId) {
        ruleTreeIndex[rule.id] = 127;
    }
    
    // Update overflow container maximum priority
    overflowMaxPriority = hybridOverflowContainer.getMaxPriority();
    
    return true;
}

bool T2Tree::tryFastInsert(T2TreeNode* root, const Rule& rule) {
    T2TreeNode* current = root;
    const int MAX_ATTEMPTS = 3;
    
    for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        if (current->isLeaf) {
            if (current->nrules < binth * 3) {
                current->classifier.push_back(rule);
                current->nrules++;
                // Maintain sorting
                std::sort(current->classifier.begin(), current->classifier.end(), 
                    [](const Rule& a, const Rule& b) { return a.priority > b.priority; });
                current->updateMaxLeafPriority();
                return true;
            }
            return false;
        }
        
        int loc = CalculateLocation(rule, current->opt, current->bit);
        if (loc == -1) return false;  // Wildcard
        
        if (loc >= static_cast<int>(current->children.size()) || !current->children[loc]) {
            if (loc >= static_cast<int>(current->children.size())) {
                current->children.resize(loc + 1, nullptr);
            }
            current->children[loc] = new T2TreeNode({rule}, current->depth + 1, true);
            current->children[loc]->parent = current;
            current->children[loc]->updateMaxLeafPriority();
            return true;
        }
        
        current = current->children[loc];
    }
    
    return false;
}

bool T2Tree::deleteFromKnownLocation(const Rule& rule, int treeIdx) {
    if (treeIdx == 127) {
        bool success = hybridOverflowContainer.remove(rule.id);
        if (success) {
            if (rule.id <= maxRuleId) {
                ruleTreeIndex[rule.id] = -1;
            }
            // Update overflow container maximum priority
            overflowMaxPriority = hybridOverflowContainer.getMaxPriority();
        }
        return success;
    }
    
    if (treeIdx >= 0 && treeIdx < normalTreeCount) {
        bool success = tryStableDelete(roots[treeIdx], rule);
        if (success) {
            if (rule.id <= maxRuleId) {
                ruleTreeIndex[rule.id] = -1;
            }
            // Update Maxpri
            Maxpri[treeIdx] = recalculateTreeMaxPriority(roots[treeIdx]);
            buildTreeSearchOrder();  // Rebuild search order
        }
        return success;
    }
    
    return false;
}

bool T2Tree::batchDelete(const std::vector<Rule>& rules) {
    int successCount = 0;
    
    std::unordered_map<int, std::vector<Rule>> treeRules;
    
    for (const auto& rule : rules) {
        if (rule.id <= maxRuleId && ruleTreeIndex[rule.id] >= 0) {
            treeRules[ruleTreeIndex[rule.id]].push_back(rule);
        }
    }
    
    for (const auto& [treeIdx, treeRuleList] : treeRules) {
        if (treeIdx == 127) {
            for (const auto& rule : treeRuleList) {
                if (hybridOverflowContainer.remove(rule.id)) {
                    successCount++;
                    if (rule.id <= maxRuleId) {
                        ruleTreeIndex[rule.id] = -1;
                    }
                }
            }
            // Update overflow container maximum priority
            overflowMaxPriority = hybridOverflowContainer.getMaxPriority();
        } else if (treeIdx < normalTreeCount) {
            for (const auto& rule : treeRuleList) {
                if (tryStableDelete(roots[treeIdx], rule)) {
                    successCount++;
                    if (rule.id <= maxRuleId) {
                        ruleTreeIndex[rule.id] = -1;
                    }
                }
            }
            // Update Maxpri for this tree
            if (successCount > 0) {
                Maxpri[treeIdx] = recalculateTreeMaxPriority(roots[treeIdx]);
            }
        }
    }
    
    if (successCount > 0) {
        buildTreeSearchOrder();  // Rebuild search order
    }
    
    return successCount > 0;
}

void T2Tree::processPendingDeletes() {
    if (updateBuffer.pendingDeletes.empty()) return;
    
    bool needRebuild = false;
    
    for (int id : updateBuffer.pendingDeletes) {
        if (id <= maxRuleId && ruleTreeIndex[id] >= 0) {
            int treeIdx = ruleTreeIndex[id];
            if (treeIdx == 127) {
                hybridOverflowContainer.remove(id);
                needRebuild = true;
            }
            ruleTreeIndex[id] = -1;
        }
    }
    
    if (needRebuild) {
        overflowMaxPriority = hybridOverflowContainer.getMaxPriority();
    }
    
    updateBuffer.pendingDeletes.clear();
}

UpdateStatistics T2Tree::performBatchUpdate(const std::vector<Rule>& rules, 
                                           const std::vector<int>& operations) {
    UpdateStatistics stats;
    
    std::vector<Rule> easyInserts;
    std::vector<Rule> hardInserts;
    std::vector<Rule> deletes;
    
    for (size_t i = 0; i < rules.size(); i++) {
        if (operations[i] == 0) {  // Insert
            if (classifyRule(rules[i]) == SPECIFIC_RULE) {
                easyInserts.push_back(rules[i]);
            } else {
                hardInserts.push_back(rules[i]);
            }
            stats.insertAttempts++;
        } else {  // Delete
            deletes.push_back(rules[i]);
            stats.deleteAttempts++;
        }
    }
    
    if (!deletes.empty()) {
        if (batchDelete(deletes)) {
            stats.deleteSuccesses = static_cast<uint32_t>(deletes.size());
        }
    }
    
    for (const auto& rule : easyInserts) {
        if (insertToShallowTree(rule)) {
            stats.insertSuccesses++;
        }
    }
    
    for (const auto& rule : hardInserts) {
        insertToOverflowDirect(rule);
        stats.insertSuccesses++;
    }
    
    if (hybridOverflowContainer.size() > 1000) {
        hybridOverflowContainer.optimize();
        overflowMaxPriority = hybridOverflowContainer.getMaxPriority();
    }
    
    updateBuffer.clear();
    
    return stats;
}

UpdateStatistics T2Tree::performStableUpdate(const std::vector<Rule>& rules, 
                                            const std::vector<int>& operations) {
    UpdateStatistics stats;
    
    if (rules.size() > 1000) {
        return performBatchUpdate(rules, operations);
    }
    
    for (size_t i = 0; i < rules.size() && i < operations.size(); i++) {
        if (operations[i] == 0) {
            stats.insertAttempts++;
            if (InsertRuleOptimized(rules[i])) {
                stats.insertSuccesses++;
            }
        } else {
            stats.deleteAttempts++;
            if (DeleteRuleOptimized(rules[i])) {
                stats.deleteSuccesses++;
            }
        }
        
        if (i % 100 == 0) {
            processPendingDeletes();
        }
        
        if (i % 500 == 0 && hybridOverflowContainer.size() > 1000) {
            hybridOverflowContainer.optimize();
            overflowMaxPriority = hybridOverflowContainer.getMaxPriority();
        }
    }
    
    processPendingDeletes();
    
    return stats;
}

// ========== Compatibility Functions ==========
bool T2Tree::InsertRuleStable(const Rule& insert_rule) {
    return InsertRuleOptimized(insert_rule);
}

bool T2Tree::DeleteRuleStable(const Rule& delete_rule) {
    return DeleteRuleOptimized(delete_rule);
}

bool T2Tree::InsertRuleCompatible(const Rule& insert_rule) {
    return InsertRuleOptimized(insert_rule);
}

bool T2Tree::DeleteRuleCompatible(const Rule& delete_rule) {
    return DeleteRuleOptimized(delete_rule);
}

bool T2Tree::InsertRuleConservative(const Rule& insert_rule) {
    return InsertRuleOptimized(insert_rule);
}

bool T2Tree::DeleteRuleSimple(const Rule& delete_rule) {
    return DeleteRuleOptimized(delete_rule);
}

bool T2Tree::tryCompatibleInsert(T2TreeNode* root, const Rule& insert_rule) {
    return tryFastInsert(root, insert_rule);
}

bool T2Tree::tryCompatibleDelete(T2TreeNode* root, const Rule& delete_rule) {
    return tryStableDelete(root, delete_rule);
}

// ========== Auxiliary Function Implementation ==========
bool T2Tree::tryStableInsert(T2TreeNode* root, const Rule& insert_rule) {
    T2TreeNode* current = root;
    int maxDepth = 15;
    
    while (current && !current->isLeaf && maxDepth-- > 0) {
        bool isWildcard = false;
        int loc = 0;
        
        for (int i = 0; i < maxBits; i++) {
            if (current->opt[i] == -1 || current->bit[i] == -1) {
                continue;
            }
            
            int t = insert_rule.Getbit(current->opt[i], current->bit[i]);
            if (t == -1) {
                isWildcard = true;
                break;
            }
            loc = (loc << 1) + t;
        }
        
        if (isWildcard) {
            if (!current->hasWRS) {
                int wildcardCount = 1;
                int suggestedCapacity = std::min(binth * 2, 30);
                current->createWRSIfBeneficial(wildcardCount, suggestedCapacity);
            }
            
            if (current->hasWRS && current->wrsNode) {
                if (current->wrsNode->addRule(insert_rule)) {
                    current->updateWRSMaxPriority();
                    return true;
                }
            }
            return false;
        }
        
        if (loc >= static_cast<int>(current->children.size())) {
            current->children.resize(loc + 1, nullptr);
        }
        
        if (!current->children[loc]) {
            std::vector<Rule> newTreeRule = {insert_rule};
            current->children[loc] = new T2TreeNode(newTreeRule, current->depth + 1, true);
            current->children[loc]->parent = current;
            current->children[loc]->updateMaxLeafPriority();
            return true;
        }
        
        current = current->children[loc];
    }
    
    if (current && current->isLeaf) {
        int dynamicCapacity = binth * 3;
        if (current->depth <= 2) {
            dynamicCapacity = binth * 4;
        }
        
        if (current->nrules < dynamicCapacity) {
            current->classifier.push_back(insert_rule);
            current->nrules++;
            current->updateMaxLeafPriority();
            
            std::sort(current->classifier.begin(), current->classifier.end(), 
                [](const Rule& a, const Rule& b) { return a.priority > b.priority; });
            return true;
        }
    }
    
    return false;
}

bool T2Tree::tryStableDelete(T2TreeNode* root, const Rule& delete_rule) {
    T2TreeNode* current = root;
    
    while (current && !current->isLeaf) {
        if (current->hasWRS && current->wrsNode) {
            if (current->wrsNode->removeRule(delete_rule)) {
                current->updateWRSMaxPriority();
                return true;
            }
        }
        
        int loc = 0;
        bool validPath = true;
        
        for (int i = 0; i < maxBits; i++) {
            if (current->opt[i] == -1 || current->bit[i] == -1) {
                continue;
            }
            
            int t = delete_rule.Getbit(current->opt[i], current->bit[i]);
            if (t == -1) {
                validPath = false;
                break;
            }
            loc = (loc << 1) + t;
        }
        
        if (!validPath || loc >= static_cast<int>(current->children.size()) || 
            !current->children[loc]) {
            return false;
        }
        
        current = current->children[loc];
    }
    
    if (current && current->isLeaf) {
        auto iter = std::find_if(current->classifier.begin(), current->classifier.end(),
            [&delete_rule](const Rule& r) { 
                return r.priority == delete_rule.priority && r.id == delete_rule.id; 
            });
        
        if (iter != current->classifier.end()) {
            current->classifier.erase(iter);
            current->nrules--;
            current->updateMaxLeafPriority();
            return true;
        }
    }
    
    return false;
}

void T2Tree::performBalancedTreeMerging() {
    if (normalTreeCount <= 3) return;
    
    std::vector<T2TreeNode*> newRoots;
    std::vector<int> newMaxpri;
    
    std::vector<std::pair<int, int>> treeSizes;
    for (int i = 0; i < normalTreeCount; i++) {
        int treeSize = countTreeRules(roots[i]);
        treeSizes.push_back({treeSize, i});
    }
    
    std::sort(treeSizes.begin(), treeSizes.end(), std::greater<std::pair<int, int>>());
    
    int keepTrees = std::max(normalTreeCount * 3 / 4, 3);
    
    for (int i = 0; i < keepTrees && i < static_cast<int>(treeSizes.size()); i++) {
        int idx = treeSizes[i].second;
        newRoots.push_back(roots[idx]);
        newMaxpri.push_back(Maxpri[idx]);
        roots[idx] = nullptr;
    }
    
    // Collect rules from small trees into overflow container
    for (size_t i = keepTrees; i < treeSizes.size(); i++) {
        int idx = treeSizes[i].second;
        if (roots[idx]) {
            std::vector<Rule> treeRules;
            extractAllRulesFromTree(roots[idx], treeRules);
            for (const auto& rule : treeRules) {
                hybridOverflowContainer.insert(rule);
                if (rule.id <= maxRuleId) {
                    ruleTreeIndex[rule.id] = 127;
                }
            }
            delete roots[idx];
            roots[idx] = nullptr;
        }
    }
    
    // Update structure
    roots = newRoots;
    Maxpri = newMaxpri;
    normalTreeCount = static_cast<int>(newRoots.size());
    
    if (hybridOverflowContainer.size() > 500) {
        hybridOverflowContainer.optimize();
        overflowMaxPriority = hybridOverflowContainer.getMaxPriority();
    }
}

int T2Tree::getBalancedAggressiveLeafCapacity(int remainingRules, int treeIndex) {
    int baseCapacity = binth;
    
    if (treeIndex == 0) {
        if (remainingRules > 90000) {
            baseCapacity = static_cast<int>(binth * 3.0);
        } else {
            baseCapacity = static_cast<int>(binth * 2.0);
        }
    } 
    else {
        double multiplier = 1.3 + (treeIndex * 0.2);
        multiplier = std::min(multiplier, 2.5);
        baseCapacity = static_cast<int>(binth * multiplier);
    }
    
    if (remainingRules < baseCapacity * 2) {
        baseCapacity = std::max(remainingRules, baseCapacity);
    }
    
    return baseCapacity;
}

// ========== Tree Construction Functions (Fixed Version) ==========
T2TreeNode* T2Tree::CreateSubT2TreeBalancedOptimized(const std::vector<Rule>& rules, 
                                                     std::vector<Rule>& kickedRules, 
                                                     int treeIndex) {
    auto* root = new T2TreeNode(rules, 1, false);
    std::queue<T2TreeNode*> que;
    que.push(root);
    
    int balancedBinth = getBalancedAggressiveLeafCapacity(static_cast<int>(rules.size()), treeIndex);
    int balancedWRSThreshold = std::max(wrsThreshold / 2, 2);
    
    while (!que.empty()) {
        T2TreeNode* node = que.front();
        que.pop();

        if (node->depth == maxLevel || node->nrules <= balancedBinth) {
            node->isLeaf = true;
            
            if (!node->classifier.empty()) {
                std::sort(node->classifier.begin(), node->classifier.end(), 
                    [](const Rule& a, const Rule& b) {
                        return a.priority > b.priority;
                    });
                node->updateMaxLeafPriority();
            }
            
            int maxAllowedInLeaf = balancedBinth + std::max(0, (maxLevel - node->depth) * 3);
            while (!node->classifier.empty() && node->nrules > maxAllowedInLeaf) {
                kickedRules.push_back(node->classifier.back());
                node->classifier.pop_back();
                node->nrules--;
            }
            
            if (!node->classifier.empty()) {
                node->updateMaxLeafPriority();
                // Record the maximum priority of leaf node
                Maxpri.back() = std::max(node->classifier[0].priority, Maxpri.back());
            }
            continue;
        }

        int Min = node->nrules, minKicked = node->nrules;
        std::vector<int> bestOpt = partitionOpt[0];
        std::vector<int> bestBit = GetSelectBit(node, partitionOpt[0]);

        for (auto opt : partitionOpt) {
            std::vector<int> subnRules(1 << maxBits, 0);
            int nKickedRules = 0;
            std::vector<int> bit = GetSelectBit(node, opt);

            for (const Rule& rule : node->classifier) {
                int loc = CalculateLocation(rule, opt, bit);
                if (loc == -1) {
                    nKickedRules++;
                } else {
                    subnRules[loc]++;
                }
            }

            int maxRule = 0;
            for (int i : subnRules) {
                maxRule = std::max(i + nKickedRules, maxRule);
            }
            if (maxRule < Min || (maxRule == Min && nKickedRules <= minKicked)) {
                Min = maxRule;
                minKicked = nKickedRules;
                bestOpt = opt;
                bestBit = bit;
            }
        }

        std::vector<int> breakOpt(maxBits, -1);
        if (bestOpt == breakOpt) {
            node->isLeaf = true;
            
            if (!node->classifier.empty()) {
                std::sort(node->classifier.begin(), node->classifier.end(), 
                    [](const Rule& a, const Rule& b) {
                        return a.priority > b.priority;
                    });
                node->updateMaxLeafPriority();
            }
            
            int maxAllowedInLeaf = balancedBinth + node->depth * 2;
            while (!node->classifier.empty() && node->nrules > maxAllowedInLeaf) {
                kickedRules.push_back(node->classifier.back());
                node->classifier.pop_back();
                node->nrules--;
            }
            
            if (!node->classifier.empty()) {
                node->updateMaxLeafPriority();
                // Fix: Record the maximum priority of leaf node
                Maxpri.back() = std::max(node->classifier[0].priority, Maxpri.back());
            }
            continue;
        }

        node->opt = bestOpt;
        node->bit = bestBit;

        std::vector<Rule> normalRules;
        std::vector<Rule> wildcardRules;
        
        for (const Rule& rule : node->classifier) {
            if (hasWildcardInSelectedBits(rule, bestOpt, bestBit)) {
                wildcardRules.push_back(rule);
            } else {
                normalRules.push_back(rule);
            }
        }

        ProcessWildcardRulesBalanced(node, wildcardRules, kickedRules, balancedWRSThreshold);

        std::vector<std::vector<Rule>> childRule(1 << maxBits);
        for (const Rule& rule : normalRules) {
            int loc = CalculateLocation(rule, bestOpt, bestBit);
            if (loc == -1) {
                kickedRules.push_back(rule);
            } else {
                childRule[loc].push_back(rule);
            }
        }

        std::vector<int> subNodeLeft = node->left;
        for (int i = 0; i < maxBits; i++) {
            if (bestOpt[i] == -1) {
                continue;
            }
            subNodeLeft[bestOpt[i]] = bestBit[i];
        }

        node->children.resize(1 << maxBits, nullptr);
        for (size_t i = 0; i < childRule.size(); i++) {
            if (!childRule[i].empty()) {
                node->children[i] = new T2TreeNode(childRule[i], node->depth + 1, false);
                node->children[i]->left = subNodeLeft;
                node->children[i]->parent = node;
                que.push(node->children[i]);
            }
        }
    }
    return root;
}

void T2Tree::ProcessWildcardRulesBalanced(T2TreeNode* node, 
                                          const std::vector<Rule>& wildcardRules,
                                          std::vector<Rule>& kickedRules,
                                          int balancedWRSThreshold) {
    if (wildcardRules.empty()) return;
    
    int highPriorityCount = 0;
    for (const Rule& rule : wildcardRules) {
        if (rule.priority > 80000) {
            highPriorityCount++;
        }
    }
    
    int adjustedThreshold = balancedWRSThreshold;
    if (highPriorityCount > static_cast<int>(wildcardRules.size()) * 0.3) {
        adjustedThreshold = std::max(adjustedThreshold / 2, 1);
    }
    
    if (static_cast<int>(wildcardRules.size()) >= adjustedThreshold) {
        int balancedWRSCapacity = std::min({
            static_cast<int>(wildcardRules.size()),
            static_cast<int>(binth * 1.3),
            15
        });
        
        if (balancedWRSCapacity >= adjustedThreshold) {
            node->createWRSIfBeneficial(static_cast<int>(wildcardRules.size()), balancedWRSCapacity);
            
            if (node->hasWRS) {
                std::vector<Rule> sortedWildcards = wildcardRules;
                std::sort(sortedWildcards.begin(), sortedWildcards.end(), 
                    [](const Rule& a, const Rule& b) {
                        return a.priority > b.priority;
                    });
                
                int added = 0;
                for (const Rule& rule : sortedWildcards) {
                    if (added < balancedWRSCapacity && node->wrsNode->addRule(rule)) {
                        added++;
                    } else {
                        kickedRules.push_back(rule);
                    }
                }
                node->updateWRSMaxPriority();
                
                // Record the maximum priority of WRS node
                if (node->maxWRSPriority > 0) {
                    Maxpri.back() = std::max(node->maxWRSPriority, Maxpri.back());
                }
                
                return;
            }
        }
    }
    
    kickedRules.insert(kickedRules.end(), wildcardRules.begin(), wildcardRules.end());
}

// ========== Bit Operation Functions ==========
bool T2Tree::hasWildcardInSelectedBits(const Rule& rule, const std::vector<int>& opt, const std::vector<int>& bit) {
    for (int i = 0; i < maxBits; i++) {
        if (opt[i] == -1 || bit[i] == -1) {
            continue;
        }
        int t = rule.Getbit(opt[i], bit[i]);
        if (t == -1) {
            return true;
        }
    }
    return false;
}

std::vector<int> T2Tree::GetSelectBit(T2TreeNode* node, std::vector<int>& opt) {
    std::vector<int> left = node->left;
    std::vector<int> bit;
    
    for (int& i : opt) {
        if (i == -1) {
            bit.push_back(-1);
            continue;
        }
        while (true) {
            bool oneFlag = false, zeroFlag = false, wildcardFlag = true;
            int field = i, bitIndex = left[i];
            for (const Rule& rule : node->classifier) {
                int t = rule.Getbit(field, bitIndex);
                if (t == -1) {
                    continue;
                } else {
                    wildcardFlag = false;
                    if (t == 1) {
                        oneFlag = true;
                    } else {
                        zeroFlag = true;
                    }
                }
                if (oneFlag && zeroFlag) {
                    break;
                }
            }
            if (oneFlag && zeroFlag) {
                break;
            }
            if (wildcardFlag) {
                left[i] = -1;
                break;
            }
            left[i]++;
        }
        bit.push_back(left[i]++);
    }
    return bit;
}

int T2Tree::CalculateLocation(const Rule& rule, const std::vector<int>& opt, const std::vector<int>& bit) {
    int loc = 0;
    
    for (int i = 0; i < maxBits; i++) {
        if (opt[i] == -1 || bit[i] == -1) {
            continue;
        }
        
        int t = rule.Getbit(opt[i], bit[i]);
        if (t == -1) {
            return -1;
        }
        
        loc = (loc << 1) + t;
    }
    
    return loc;
}

inline int T2Tree::CalculatePacketLocation(const Packet& p, const std::vector<int>& opt, const std::vector<int>& bit) {
    static const std::vector<int> maxMask = {31, 31, 15, 15, 7};
    int loc = 0;
    
    for (int i = 0; i < maxBits; i++) {
        if (opt[i] == -1 || bit[i] == -1) {
            continue;
        }
        
        loc <<= 1;
        if (p[opt[i]] & (1 << (maxMask[opt[i]] - bit[i]))) {
            loc++;
        }
    }
    
    return loc;
}

// T2Tree.cpp

double T2Tree::AverageLeafDepth() const {
    long long sumDepth = 0;
    long long leafCount = 0;
    for (int i = 0; i < normalTreeCount; ++i) {
        if (!roots[i]) continue;
        std::queue<T2TreeNode*> q;
        q.push(roots[i]);
        while (!q.empty()) {
            T2TreeNode* node = q.front(); q.pop();
            if (node->isLeaf) {
                sumDepth += node->depth;
                ++leafCount;
            }
            for (auto* ch : node->children) if (ch) q.push(ch);
        }
    }
    if (leafCount == 0) return 0.0;
    return static_cast<double>(sumDepth) / static_cast<double>(leafCount);
}

double T2Tree::AverageNodeBalance() const {
    long long nodeCount = 0;
    long double sumBalance = 0.0L;

    auto calcRules = [&](T2TreeNode* n)->int {
        return countTreeRules(n); // Already have private const function, including leaf rules and WRS
    };

    for (int i = 0; i < normalTreeCount; ++i) {
        if (!roots[i]) continue;
        std::queue<T2TreeNode*> q;
        q.push(roots[i]);
        while (!q.empty()) {
            T2TreeNode* node = q.front(); q.pop();
            if (node->isLeaf) {
                // Leaf nodes are excluded from balance degree calculation as they have no children
            } else {
                std::vector<int> sizes;
                sizes.reserve(node->children.size());
                for (auto* ch : node->children) {
                    if (ch) {
                        sizes.push_back(calcRules(ch));
                    }
                }
                if (sizes.size() >= 2) {
                    long long sum = 0;
                    int mn = INT_MAX, mx = 0;
                    for (int v : sizes) { sum += v; mn = std::min(mn, v); mx = std::max(mx, v); }
                    double bal = 1.0 - (static_cast<double>(mx - mn) /
                                        static_cast<double>(std::max<long long>(1, sum)));
                    sumBalance += bal;
                    ++nodeCount;
                }
            }
            for (auto* ch : node->children) if (ch) q.push(ch);
        }
    }
    if (nodeCount == 0) return 0.0;
    return static_cast<double>(sumBalance / nodeCount);
}
