#ifndef  ELEM_H
#define  ELEM_H

#include <vector>
#include <queue>
#include <list>
#include <set>
#include <map>
#include <unordered_map>
#include <iostream>
#include <algorithm>
#include <random>
#include <numeric>
#include <math.h>
#include <memory>
#include <chrono>
#include <array>
#include <vector>

#define MAXDIMENSIONS 5
#define MAXCUTS1 64  //keys for memory consumption
#define MAXCUTS2 8   //keys for memory consumption
#define MAXCUTBITS1 int(log(MAXCUTS1)/log(2))
#define ANDBITS1 (1<<MAXCUTBITS1) -1
#define MAXCUTBITS2 int(log(MAXCUTS2)/log(2))
#define ANDBITS2 (1<<MAXCUTBITS2) -1
#define MAXNODES 5000000
#define MAXRULES 1000000
#define MAXPACKETS 1000000 //to avoid segmentation fault, please change stack size to 81920 or larger, run "ulimit -s 81920"
#define MAXBUCKETS 40
#define RULE_SIZE 16
#define NODE_SIZE 32
#define LEAF_NODE_SIZE 4
#define TREE_NODE_SIZE 8
#define Null -1
#define PTR_SIZE 4
#define HEADER_SIZE 4
#define RULESIZE 4.5


#define FieldSA 0
#define FieldDA 1
#define FieldSP 2
#define FieldDP 3
#define FieldProto 4

#define LowDim 0
#define HighDim 1

#define POINT_SIZE_BITS 32

typedef uint32_t Point;
typedef std::vector<Point> Packet;
typedef uint32_t Memory;

enum NodeType {Cuts, Linear, WRS};

struct Rule {
    //Rule(){};
    //
    Rule(int dim = 5) : dim(dim), priority(0), id(0), tag(0), markedDelete(0), 
                        prefix_length(dim, 0), range(dim, {{0, 0}}) { }

    int dim;
    int priority;

    int id;
    int tag;
    bool markedDelete = 0;

    std::vector<unsigned> prefix_length;

    std::vector<std::array<Point, 2>> range;

    inline bool MatchesPacket(const Packet &p) const {
        if (p[0] < range[0][LowDim] || p[0] > range[0][HighDim]) return false;
        if (p[1] < range[1][LowDim] || p[1] > range[1][HighDim]) return false;
        if (p[2] < range[2][LowDim] || p[2] > range[2][HighDim]) return false;
        if (p[3] < range[3][LowDim] || p[3] > range[3][HighDim]) return false;
        if (p[4] < range[4][LowDim] || p[4] > range[4][HighDim]) return false;
        return true;
    }

    // //  Ban SIMD
    // inline bool MatchesPacketSIMD(const Packet &p) const {
    //     return MatchesPacket(p);  
    // }

    int inline Getbit(int field, int bit) const {
        if(prefix_length[field] <= bit) {
            return -1;
        }
        switch(field) {
            case FieldSA: case FieldDA: {
                int tmp = (1 << (31 - bit));
                if(range[field][LowDim] & range[field][HighDim] & tmp) {
                    return 1;
                } else {
                    return 0;
                }
            }
            case FieldSP: case FieldDP: {
                int tmp = (1 << (15 - bit));
                if(range[field][LowDim] & range[field][HighDim] & tmp) {
                    return 1;
                } else {
                    return 0;
                }
            }
            case FieldProto: {
                int tmp = (1 << (7 - bit));
                if(range[field][LowDim] & range[field][HighDim] & tmp) {
                    return 1;
                } else {
                    return 0;
                }
            }

            default:
                printf("rule doesn't have this field: %d\n", field);
                exit(-2);
        }
        return -1;
    }

    bool operator<(const Rule r) const{
        return priority > r.priority;
    }

    bool operator == (const Rule r) {
        return r.priority == priority;
    }

    void Print() const {
        for (int i = 0; i < dim; i++) {
            printf("%u:%u ", range[i][LowDim], range[i][HighDim]);
        }
        printf("\n");
        for(int i : prefix_length) {
            printf("%d  ", i);
        }
        printf("\n");
    }
};

class PacketClassifier {
public:
    virtual ~PacketClassifier() = default;
    
    virtual void ConstructClassifier(const std::vector<Rule> &rules) = 0;

    virtual int ClassifyAPacket(const Packet &packet) = 0;

    virtual void DeleteRule(const Rule &rule) = 0;

    virtual void InsertRule(const Rule &rule) = 0;

    virtual Memory MemSizeBytes() const = 0;

    virtual int MemoryAccess() const { return queryCount;}

    virtual int WorstMemoryAccess() const { return worstQuery;}

    virtual size_t NumTables() const = 0;

    virtual size_t RulesInTable(size_t tableIndex) const = 0;

    int TablesQueried() const { return queryCount; }

protected:
    void QueryUpdate(uint64_t query) {
        packetHistogram[query]++;
        worstQuery = std::max(worstQuery, query);
        queryCount += query;
    }

private:
    uint64_t queryCount = 0;
    uint64_t worstQuery = 0;
    std::unordered_map<int, int> packetHistogram;
};

inline void SortRules(std::vector<Rule> &rules) {
    sort(rules.begin(), rules.end(), [](const Rule &rx, const Rule &ry) { return rx.priority >= ry.priority; });
}

inline void SortRules(std::vector<Rule *> &rules) {
    sort(rules.begin(), rules.end(), [](const Rule *rx, const Rule *ry) { return rx->priority >= ry->priority; });
}


class Interval {
public:
    Interval() {}

    virtual Point GetLowPoint() const = 0;

    virtual Point GetHighPoint() const = 0;

    virtual void Print() const = 0;
};

class interval : public Interval {
public:
    interval(unsigned int a, unsigned int b, int id) : a(a), b(b), id(id) {}

    Point GetLowPoint() const { return a; }

    Point GetHighPoint() const { return b; }

    void Print() const {};

    Point a, b;

    bool operator<(const interval &rhs) const {
        if (a != rhs.a) {
            return a < rhs.a;
        } else return b < rhs.b;
    }

    bool operator==(const interval &rhs) const {
        return a == rhs.a && b == rhs.b;
    }

    int id;
    int weight;

};

struct EndPoint {
    EndPoint(double val, bool isRightEnd, int id) : val(val), isRightEnd(isRightEnd), id(id) {}

    bool operator<(const EndPoint &rhs) const {
        return val < rhs.val;
    }

    double val;
    bool isRightEnd;
    int id;
};

#endif