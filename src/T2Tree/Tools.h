// Tools.h
#ifndef T2_TOOLS_H
#define T2_TOOLS_H

#include "T2Tree.h"
#include <iostream>
#include <queue>

class Tools {
public:
    // Level order traversal to display tree structure
    static void LevelTraverse(T2TreeNode *root);
    
    // Display WRS statistics
    static void ShowWRSStatistics(T2TreeNode *root);
    
    // Calculate tree depth
    static int CalculateTreeDepth(T2TreeNode *root);
    
    // Calculate total number of WRS nodes
    static int CountWRSNodes(T2TreeNode *root);
    
    // Calculate total number of rules
    static int CountTotalRules(T2TreeNode *root);
    
    // Display detailed tree structure information
    static void PrintTreeStructure(T2TreeNode *root, int indent = 0);
    
    // Analyze WRS usage in T2Tree
    static void AnalyzeWRSUsage(const T2Tree& classifier);
};

#endif // T2_TOOLS_H