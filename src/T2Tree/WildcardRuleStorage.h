#ifndef WILDCARD_RULE_STORAGE_H
#define WILDCARD_RULE_STORAGE_H

#include "../ElementaryClasses.h"
#include <vector>
#include <algorithm>
#include <set>

class WildcardRuleStorage {
public:
    explicit WildcardRuleStorage(int capacity = 10);
    ~WildcardRuleStorage() = default;

    // Add rule to WRS
    bool addRule(const Rule& rule);
    
    // Remove rule
    bool removeRule(const Rule& rule);
    
    // Search for matching rules, return highest priority
    int searchHighestPriority(const Packet& packet);
    
    // Search for all matching rules
    std::vector<Rule> searchAllMatches(const Packet& packet);
    
    // Get rule count
    size_t size() const { return rules.size(); }
    
    // Check if there is still capacity
    bool hasCapacity() const { return static_cast<int>(rules.size()) < capacity; }
    
    // Get capacity
    int getCapacity() const { return capacity; }
    
    // Ensure rules are sorted by priority
    void ensureSorted();
    
    // Clear WRS
    void clear();
    
    // Get rule reference (ensure sorted)
    const std::vector<Rule>& getRules() const;
    
    // Get rule copy (for statistics)
    std::vector<Rule> getRulesCopy() const;
    
    // Validate WRS internal state
    bool validateState() const;

private:
    std::vector<Rule> rules;
    int capacity;
    bool sorted;
    
    void sortRules();
};

#endif // WILDCARD_RULE_STORAGE_H