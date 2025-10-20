#include "WildcardRuleStorage.h"
#include <iostream>

WildcardRuleStorage::WildcardRuleStorage(int capacity) : capacity(capacity), sorted(true) {
    rules.reserve(capacity);
}

bool WildcardRuleStorage::addRule(const Rule& rule) {
    if (static_cast<int>(rules.size()) >= capacity) {
        return false;
    }
    
    rules.push_back(rule);
    sorted = false;
    return true;
}

bool WildcardRuleStorage::removeRule(const Rule& rule) {
    auto it = std::find_if(rules.begin(), rules.end(), 
        [&rule](const Rule& r) { return r.id == rule.id; });
    
    if (it != rules.end()) {
        rules.erase(it);
        sorted = false;
        return true;
    }
    
    return false;
}

int WildcardRuleStorage::searchHighestPriority(const Packet& packet) {
    if (rules.empty()) {
        return -1;
    }
    
    ensureSorted();
    
    int highestPriority = -1;
    
    // Since rules are sorted by priority, return the first match
    for (const Rule& rule : rules) {
        if (rule.MatchesPacket(packet)) {
            return rule.priority;  // Directly return the first match (highest priority)
        }
    }
    
    return highestPriority;
}

std::vector<Rule> WildcardRuleStorage::searchAllMatches(const Packet& packet) {
    std::vector<Rule> matches;
    
    for (const Rule& rule : rules) {
        if (rule.MatchesPacket(packet)) {
            matches.push_back(rule);
        }
    }
    
    std::sort(matches.begin(), matches.end(), 
        [](const Rule& a, const Rule& b) {
            return a.priority > b.priority;
        });
    
    return matches;
}

void WildcardRuleStorage::ensureSorted() {
    if (!sorted) {
        sortRules();
        sorted = true;
    }
}

void WildcardRuleStorage::sortRules() {
    std::sort(rules.begin(), rules.end(), 
        [](const Rule& a, const Rule& b) {
            return a.priority > b.priority;
        });
}

void WildcardRuleStorage::clear() {
    rules.clear();
    sorted = true;
}

std::vector<Rule> WildcardRuleStorage::getRulesCopy() const {
    return rules;
}

const std::vector<Rule>& WildcardRuleStorage::getRules() const {
    const_cast<WildcardRuleStorage*>(this)->ensureSorted();
    return rules;
}

bool WildcardRuleStorage::validateState() const {
    if (static_cast<int>(rules.size()) > capacity) {
        return false;
    }
    
    if (sorted && rules.size() > 1) {
        for (size_t i = 1; i < rules.size(); i++) {
            if (rules[i-1].priority < rules[i].priority) {
                return false;
            }
        }
    }
    
    std::set<int> ruleIds;
    for (const Rule& rule : rules) {
        if (ruleIds.find(rule.id) != ruleIds.end()) {
            return false;
        }
        ruleIds.insert(rule.id);
    }
    
    return true;
}