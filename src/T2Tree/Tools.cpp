// Tools.cpp
#include "Tools.h"

void Tools::LevelTraverse(T2TreeNode *root) {
    if (!root) return;
    
    std::queue<T2TreeNode*> que;
    que.push(root);
    int level = 0;
    
    std::vector<int> MaxTuple = {32, 32, 16, 16, 8};
    
    while (!que.empty()) {
        size_t levelSize = que.size();
        std::cout << "Level " << level << ": ";
        
        for (size_t i = 0; i < levelSize; i++) {
            auto node = que.front();
            que.pop();
            
            std::cout << "[Rules:" << node->nrules;
            if (node->hasWRS && node->wrsNode) {
                std::cout << ", WRS:" << node->wrsNode->size();
            }
            std::cout << "] ";
            
            for (auto iter : node->children) {
                if (iter) {
                    que.push(iter);
                }
            }
            
            if (node->isLeaf) {
                for (size_t j = 0; j < node->left.size() && j < MaxTuple.size(); j++) {
                    MaxTuple[j] = std::min(node->left[j], MaxTuple[j]);
                }
            }
        }
        std::cout << std::endl;
        level++;
    }
    
    std::cout << "MaxTuple: ";
    for (auto iter : MaxTuple) {
        std::cout << iter << " ";
    }
    std::cout << std::endl;
}

void Tools::ShowWRSStatistics(T2TreeNode *root) {
    if (!root) return;
    
    std::queue<T2TreeNode*> que;
    que.push(root);
    
    int totalWRSNodes = 0;
    int totalWRSRules = 0;
    int maxWRSRulesInNode = 0;
    
    while (!que.empty()) {
        auto node = que.front();
        que.pop();
        
        if (node->hasWRS && node->wrsNode) {
            totalWRSNodes++;
            int wrsRules = static_cast<int>(node->wrsNode->size());
            totalWRSRules += wrsRules;
            maxWRSRulesInNode = std::max(maxWRSRulesInNode, wrsRules);
        }
        
        for (auto iter : node->children) {
            if (iter) {
                que.push(iter);
            }
        }
    }
    
    std::cout << "Total WRS nodes: " << totalWRSNodes << std::endl;
    std::cout << "Total WRS rules: " << totalWRSRules << std::endl;
    std::cout << "Max WRS rules per node: " << maxWRSRulesInNode << std::endl;
}

int Tools::CalculateTreeDepth(T2TreeNode *root) {
    if (!root) return 0;
    
    int maxDepth = 0;
    std::queue<std::pair<T2TreeNode*, int>> que;
    que.push({root, 0});
    
    while (!que.empty()) {
        auto [node, depth] = que.front();
        que.pop();
        
        maxDepth = std::max(maxDepth, depth);
        
        for (auto child : node->children) {
            if (child) {
                que.push({child, depth + 1});
            }
        }
    }
    
    return maxDepth;
}

int Tools::CountWRSNodes(T2TreeNode *root) {
    if (!root) return 0;
    
    int count = 0;
    std::queue<T2TreeNode*> que;
    que.push(root);
    
    while (!que.empty()) {
        auto node = que.front();
        que.pop();
        
        if (node->hasWRS && node->wrsNode) {
            count++;
        }
        
        for (auto child : node->children) {
            if (child) {
                que.push(child);
            }
        }
    }
    
    return count;
}

int Tools::CountTotalRules(T2TreeNode *root) {
    if (!root) return 0;
    
    int count = 0;
    std::queue<T2TreeNode*> que;
    que.push(root);
    
    while (!que.empty()) {
        auto node = que.front();
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

void Tools::PrintTreeStructure(T2TreeNode *root, int indent) {
    if (!root) return;
    
    for (int i = 0; i < indent; i++) {
        std::cout << "  ";
    }
    
    std::cout << "Node[depth=" << root->depth 
              << ", rules=" << root->nrules;
    
    if (root->hasWRS && root->wrsNode) {
        std::cout << ", WRS=" << root->wrsNode->size();
    }
    
    if (root->isLeaf) {
        std::cout << ", LEAF";
    }
    
    std::cout << "]" << std::endl;
    
    for (size_t i = 0; i < root->children.size(); i++) {
        if (root->children[i]) {
            for (int j = 0; j < indent + 1; j++) {
                std::cout << "  ";
            }
            std::cout << "Child[" << i << "]:" << std::endl;
            PrintTreeStructure(root->children[i], indent + 2);
        }
    }
}

void Tools::AnalyzeWRSUsage(const T2Tree& classifier) {
    std::cout << "Total subtrees: " << classifier.NumTables() << std::endl;
    std::cout << "Algorithm: Adaptive Hierarchical Packet Tree with Optimized Two-Phase Search" << std::endl;
}