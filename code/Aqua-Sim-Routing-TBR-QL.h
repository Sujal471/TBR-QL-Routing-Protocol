#ifndef AQUA_SIM_ROUTING_TBR_H
#define AQUA_SIM_ROUTING_TBR_H

#include "aqua-sim-routing.h"
#include "aqua-sim-address.h"
#include "aqua-sim-header.h"
#include "ns3/vector.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/event-id.h"
#include "ns3/random-variable-stream.h"
#include <map>
#include <set>
#include <tuple>

namespace ns3 {

// ═══════════════════════════════════════════════════════════
// MESSAGE TYPE CONSTANTS
// ═══════════════════════════════════════════════════════════
#define TBR_DATA          0x01   // normal data packet
#define TBR_HELLO         0x02   // hello/discovery broadcast
#define TBR_TRUST_UPDATE  0x03   // trust change broadcast

// ═══════════════════════════════════════════════════════════
// NEIGHBOR TABLE ENTRY
// One entry per neighbor node that this node knows about
// ═══════════════════════════════════════════════════════════
struct TBRNeighborEntry {
    // ── Identity ──
    uint32_t nodeId;
    
    // ── Position ──
    double   x, y, z;           // 3D coordinates from hello packet
    double   distance;           // precomputed Euclidean distance
    
    // ── Energy ──
    double   initialEnergy;      // E0 — reported at first hello
    double   currentEnergy;      // Ej — updated every hello broadcast
    double   energyRatio;        // Ej/E0 — used in Ph formula
    
    // ── Interaction Counters ──
    uint32_t successfulPackets;  // aij — confirmed forwards by j
    uint32_t droppedPackets;     // bij — timeouts/drops by j
    
    // ── Direct Trust (Interaction Trust only) ──
    // Ts = (1/(bij+1)) * (aij/(aij+bij))
    double   Ts;                 // interaction trust
    double   TD;                 // direct trust = Ts in this implementation
    
    // ── Integrated Trust (Direct + Indirect combined) ──
    double   TG;                 // final trust used in Ph
    double   previousTD;         // stored for broadcast delta check
    double Te;
    double   Tr;
    // ── Routing Metric ──
    double   Ph;                 // relay evaluation score
    
    // ── Validity ──
    bool     isAlive;
    double   lastHeardTime;      // last hello/packet received time

    // ── Constructor with safe defaults ──
    TBRNeighborEntry()
      : nodeId(0), x(0), y(0), z(0), distance(0),
        initialEnergy(10.0), currentEnergy(10.0), energyRatio(1.0),
        successfulPackets(0), droppedPackets(0),
        Ts(0.5), TD(0.5), TG(0.5), previousTD(0.5),Te(1.0),Tr(0.5),
        Ph(0.0), isAlive(true), lastHeardTime(0.0) {}
};

// ═══════════════════════════════════════════════════════════
// INDIRECT TRUST TABLE ENTRY
// At node i, for neighbor j, store what recommender k says about j
// ═══════════════════════════════════════════════════════════
struct TBRIndirectEntry {
    uint32_t aboutNodeId;       // j — whose trust this describes
    uint32_t recommenderNodeId; // k — who gave this recommendation
    double   trustValue;        // k's direct trust TD for j
    double   timestamp;         // when this recommendation arrived
    
    TBRIndirectEntry()
      : aboutNodeId(0), recommenderNodeId(0),
        trustValue(0.5), timestamp(0.0) {}
};

// ═══════════════════════════════════════════════════════════
// WATCHDOG ENTRY
// Tracks every packet node i sent to neighbor j,
// waiting to confirm j forwarded it
// ═══════════════════════════════════════════════════════════
struct TBRWatchdogEntry {
    uint32_t  packetId;          // unique packet id
    uint32_t  originalSrc;       // who created the packet
    uint32_t  sentToNode;        // which neighbor i sent to (j)
    double    sentTimestamp;     // simulation time when sent
    double    theoreticalDelay;  // precomputed max allowed delay
    bool      confirmed;         // set true when overheard forwarded
    EventId   timeoutEvent;      // NS3 timer — fires on drop
    
    TBRWatchdogEntry()
      : packetId(0), originalSrc(0), sentToNode(0),
        sentTimestamp(0), theoreticalDelay(0),
        confirmed(false) {}
};

// Key to look up watchdog entry
// (packetId, originalSrc, sentToNode)
using TBRWatchdogKey = std::tuple<uint32_t, uint32_t, uint32_t>;

// ═══════════════════════════════════════════════════════════
// TBR PACKET HEADER
// Carried in every TBR packet
// ═══════════════════════════════════════════════════════════
class TBRHeader : public Header {
public:
    // ── Packet chain fields ──
    uint8_t  msgType;           // TBR_DATA / TBR_HELLO / TBR_TRUST_UPDATE
    uint32_t originalSrc;       // who created this data
    uint32_t packetId;          // unique id at source
    uint32_t prevSender;        // who sent this copy to lastSender
    uint32_t lastSender;        // who is currently forwarding
    uint32_t hopCount;
    uint32_t intendedNextHop;   // next hop intended by sender
    double   sendTimestamp;     // when lastSender transmitted
    
    // ── Position of lastSender (for routing decisions) ──
    double   senderX, senderY, senderZ;
    double   senderEnergy;      // current energy of lastSender
    
    // ── Trust update fields (used when msgType=TBR_TRUST_UPDATE) ──
    uint32_t aboutNodeId;       // whose trust changed
    double   oldTrust;          // previous TG value
    double   newTrust;          // current TG value
    uint32_t interactionCount;  // total aij+bij at broadcaster

    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    void   Print(std::ostream &os) const override;
    uint32_t GetSerializedSize() const override;
    void   Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;

    TBRHeader()
      : msgType(TBR_DATA), originalSrc(0), packetId(0),
        prevSender(0), lastSender(0), hopCount(0), sendTimestamp(0),
        senderX(0), senderY(0), senderZ(0), senderEnergy(100.0),
        aboutNodeId(0), oldTrust(0.5), newTrust(0.5),intendedNextHop(0),
        interactionCount(0) {}
};

// ═══════════════════════════════════════════════════════════
// TBR ROUTING PROTOCOL CLASS
// ═══════════════════════════════════════════════════════════
class AquaSimTBR : public AquaSimRouting {
public:
    AquaSimTBR();
    static TypeId GetTypeId();
    int64_t AssignStreams(int64_t stream);

    // ── Main entry from NS3 ──
    virtual bool Recv(Ptr<Packet> packet,
                      const Address &dest,
                      uint16_t protocolNumber) override;

    

    // ── Malicious node control (for simulation) ──
    static void AddMaliciousNode(AquaSimAddress addr) {
        s_maliciousNodes.insert(addr);
    }
    static bool IsMalicious(AquaSimAddress addr) {
        return s_maliciousNodes.count(addr) > 0;
    }
    static std::set<uint32_t> s_delayAttackers;

// ADD static methods:
static void AddDelayAttacker(uint32_t nodeId) {
    s_delayAttackers.insert(nodeId);
}
static bool IsDelayAttacker(uint32_t nodeId) {
    return s_delayAttackers.count(nodeId) > 0;
}
static std::set<uint32_t> s_broadcastAttackers;

// ADD static methods:
static void AddBroadcastAttacker(uint32_t nodeId) {
    s_broadcastAttackers.insert(nodeId);
}
static bool IsBroadcastAttacker(uint32_t nodeId) {
    return s_broadcastAttackers.count(nodeId) > 0;
}
    static constexpr uint32_t SINK_ACK_NEXTHOP = 10000;
static std::set<uint32_t> s_sinkNodes;

// ADD static method to insert sink IDs:
static void AddSinkNode(uint32_t nodeId) {
    s_sinkNodes.insert(nodeId);
}
static bool IsSink(uint32_t nodeId) {
    return s_sinkNodes.count(nodeId) > 0;
}
    // ── Statistics ──
    static uint32_t GetPacketsAtSink()  { return s_packetsAtSink; }
    static uint32_t GetPacketsAtSource() { return g_packetsSentBySource; }
    static double   GetTotalDelay()     { return s_totalDelay; }
    static double   GetAverageDelay() {
        return (s_packetsAtSink > 0)
               ? s_totalDelay / s_packetsAtSink : 0.0;
    }
static std::vector<AquaSimTBR*> s_allInstances;

static void RegisterInstance(AquaSimTBR* inst) {
    s_allInstances.push_back(inst);
}
// ── Global snapshot storage ──
// Outer index = snapshot number (0 = t=2000, 1 = t=4000 ...)
// Inner index = 0:Normal  1:Drop  2:Delay  3:Broadcast
struct QSnapshot {
    double simTime;
    double avgNormal;
    double avgDrop;
    double avgDelay;
    double avgBroadcast;
};
static std::vector<QSnapshot> s_qSnapshots;
struct PhSnapshot {
    double simTime;
    // Ph values
    double phNormal;
    double phDrop;
    double phDelay;
    double phBroadcast;
    // TG values
    double tgNormal;
    double tgDrop;
    double tgDelay;
    double tgBroadcast;
    // TD values
    double tdNormal;
    double tdDrop;
    double tdDelay;
    double tdBroadcast;
};
static std::vector<PhSnapshot> s_phSnapshots;
// ── Helper: averages Ph, TG, or TD for a node set ──
// mode: 0=Ph  1=TG  2=TD
// Depth filter: only include where myZ > neighborZ
static double GetAverageMetricForNodes(
    const std::set<uint32_t>& targetNodes,
    int mode)
{
    double   sum = 0.0;
    uint32_t cnt = 0;

    for (AquaSimTBR* inst : s_allInstances) {

        Ptr<MobilityModel> myMob =
            inst->GetNetDevice()->GetNode()
                ->GetObject<MobilityModel>();
        if (!myMob) continue;

        double myZ = myMob->GetPosition().z;

        for (auto& kv : inst->m_neighborTable) {
            uint32_t neighborId = kv.first;

            if (!targetNodes.count(neighborId)) continue;

            TBRNeighborEntry& entry = kv.second;

            // Only valid upward routing direction
            if (myZ <= entry.z) continue;

            switch(mode) {
                case 0: sum += entry.Ph; break;
                case 1: sum += entry.TG; break;
                case 2: sum += entry.TD; break;
            }
            cnt++;
        }
    }
    return (cnt > 0) ? sum / cnt : 0.0;
}

// ── Convenience wrappers ──
static double GetAveragePhForNodes(
    const std::set<uint32_t>& t) {
    return GetAverageMetricForNodes(t, 0);
}
static double GetAverageTGForNodes(
    const std::set<uint32_t>& t) {
    return GetAverageMetricForNodes(t, 1);
}
static double GetAverageTDForNodes(
    const std::set<uint32_t>& t) {
    return GetAverageMetricForNodes(t, 2);
}

// ── Store one combined snapshot ──
static void StorePhSnapshot(
    double simTime,
    double phN,  double phD,  double phDl, double phB,
    double tgN,  double tgD,  double tgDl, double tgB,
    double tdN,  double tdD,  double tdDl, double tdB)
{
    PhSnapshot s;
    s.simTime     = simTime;
    s.phNormal    = phN;  s.phDrop      = phD;
    s.phDelay     = phDl; s.phBroadcast = phB;
    s.tgNormal    = tgN;  s.tgDrop      = tgD;
    s.tgDelay     = tgDl; s.tgBroadcast = tgB;
    s.tdNormal    = tdN;  s.tdDrop      = tdD;
    s.tdDelay     = tdDl; s.tdBroadcast = tdB;
    s_phSnapshots.push_back(s);
}
// ── Updated GetAverageQForNodes ──
// Only include Q(i,j) where:
//   myNodeId (node i) is DEEPER than neighborId (node j)
//   i.e. z_i > z_j  →  valid routing direction only
static double GetAverageQForNodes(
    const std::set<uint32_t>& targetNodes)
{
    double   sum = 0.0;
    uint32_t cnt = 0;

    for (AquaSimTBR* inst : s_allInstances) {

        // Get depth of this node (the one whose Q-table we read)
        Ptr<Node> node =
            inst->GetNetDevice()->GetNode();
        if (!node) continue;

        Ptr<MobilityModel> myMob =
            node->GetObject<MobilityModel>();
        if (!myMob) continue;

        double myZ = myMob->GetPosition().z;

        for (auto& kv : inst->m_qTable) {
            uint32_t myId       = kv.first.first;
            uint32_t neighborId = kv.first.second;

            // Only consider target category neighbors
            if (!targetNodes.count(neighborId)) continue;

            // Only include if this node is DEEPER than neighbor
            // (routing goes from deeper to shallower)
            // Look up neighbor's z from this node's neighbor table
            if (!inst->m_neighborTable.count(neighborId))
                continue;

            double neighborZ =
                inst->m_neighborTable[neighborId].z;

            // myZ > neighborZ means this node is deeper
            // and neighbor is a valid upward hop
            if (myZ <= neighborZ) continue;

            sum += kv.second;
            cnt++;
        }
    }
    return (cnt > 0) ? sum / cnt : 0.0;
}

// ── Print and store one snapshot ──
static void StoreQSnapshot(
    double simTime,
    double qNormal,
    double qDrop,
    double qDelay,
    double qBroadcast)
{
    QSnapshot snap;
    snap.simTime      = simTime;
    snap.avgNormal    = qNormal;
    snap.avgDrop      = qDrop;
    snap.avgDelay     = qDelay;
    snap.avgBroadcast = qBroadcast;
    s_qSnapshots.push_back(snap);
}
void SendHello();
void SendSinkAck(uint32_t prevSenderNodeId);
using RepeatKey = std::tuple<uint32_t, uint32_t, uint32_t>;
std::map<RepeatKey, uint32_t> m_repeatCount;

void CheckRepeatTrust(uint32_t originalSrc,
                      uint32_t packetId,
                      uint32_t lastSender);
// ADD in protected section:
void DelayedForward(Ptr<Packet>   packet,
                    AquaSimHeader ash,
                    TBRHeader     hdr,
                    uint32_t      nextHop);
void RebroadcastPacket(Ptr<Packet> packet,
                       TBRHeader   hdr,
                       uint32_t    nextHop,
                       int         remaining);                    
void   DoInitialize() override;
protected:
    // ── Simulation parameters ──
    double   m_commRange;       // communication range (meters)
    double   m_lambda;          // Ph weight (energy vs trust), default 0.5
    double   m_sigma;           // Ph distance scaling, default 1.0
    double   m_trustThreshold;  // below this TG → node is suspect
    double   m_broadcastDelta;  // min TG change to trigger broadcast
    double   m_helloInterval;   // seconds between hello broadcasts
    double   m_watchdogTimeout; // multiplier on theoreticalDelay
    uint32_t m_maxHops;         // max hops before dropping packet

    // ── Per-node state ──
    uint32_t m_myNodeId;
    uint32_t m_packetCounter;   // increments per sent packet

    // ── TABLE 1: Neighbor Table (Direct Trust) ──
    // Key = neighbor nodeId
    std::map<uint32_t, TBRNeighborEntry> m_neighborTable;

    // ── TABLE 2: Indirect Trust Table ──
    // Outer key = aboutNodeId (j)
    // Inner key = recommenderNodeId (k)
    std::map<uint32_t,
             std::map<uint32_t, TBRIndirectEntry>> m_indirectTrustTable;

    // ── Computed TI per node (cached result) ──
    std::map<uint32_t, double> m_TI;

    // ── Watchdog Table ──
    std::map<TBRWatchdogKey, TBRWatchdogEntry> m_watchdogTable;

    // ── Seen packets (for duplicate detection) ──
    // Key = (originalSrc, packetId)
    std::set<std::pair<uint32_t,uint32_t>> m_seenPackets;
    using DelayKey = std::tuple<uint32_t, uint32_t, uint32_t>;
std::map<DelayKey, double> m_sendDelayTime;

    // ── Packet send times (for delay tracking) ──
    using SendTimeKey = std::pair<uint32_t, uint32_t>;
// first  = originalSrc
// second = packetId
    static std::map<SendTimeKey, double> m_sendTime;
    // ── Static globals ──
    static std::set<AquaSimAddress> s_maliciousNodes;
    static uint32_t  s_packetsAtSink;
    static uint32_t  g_packetsSentBySource; // global count of packets created at source
    static double    s_totalDelay;

    Ptr<UniformRandomVariable> m_rand;

    // ════════════════════════════════════
    // PHASE 1: DISCOVERY (0-100 seconds)
    // ════════════════════════════════════
    void StartDiscovery();
    //void SendHello();
    void HandleHello(TBRHeader &hdr, double recvTime);

    // ════════════════════════════════════
    // PHASE 2: ACTIVE ROUTING
    // ════════════════════════════════════
    void RoutePacket(Ptr<Packet> pkt, TBRHeader &hdr);
    void DataForSink(Ptr<Packet> pkt, TBRHeader &hdr);
    uint32_t SelectNextHop();           // returns nodeId with highest Ph
    void ForwardPacket(Ptr<Packet> pkt, TBRHeader &hdr, uint32_t nextHop);

    // ════════════════════════════════════
    // WATCHDOG FUNCTIONS
    // ════════════════════════════════════
    void CreateWatchdog(uint32_t packetId, uint32_t originalSrc,
                        uint32_t sentToNode, double sentTime);
    void CheckWatchdog(TBRHeader &hdr);          // called on overheard packet
    void WatchdogTimeout(TBRWatchdogKey key);    // called when timer fires

    // ════════════════════════════════════
    // TRUST COMPUTATION
    // ════════════════════════════════════
    void   UpdateTrustOnSuccess(uint32_t neighborId, double actualDelay);
    void   UpdateTrustOnDrop(uint32_t neighborId);
    void   RecomputeInteractionTrust(uint32_t neighborId);
    double ComputeIndirectTrust(uint32_t nodeId);
    void   RecomputeTG(uint32_t neighborId);
    double ComputePh(uint32_t neighborId);
    double ComputeTheoreticalDelay(uint32_t neighborId);

    // ════════════════════════════════════
    // BROADCAST FUNCTIONS
    // ════════════════════════════════════
    void BroadcastTrustUpdate(uint32_t aboutNodeId,
                               double oldTG, double newTG);
    void HandleTrustUpdate(TBRHeader &hdr);

    // ════════════════════════════════════
    // UTILITY
    // ════════════════════════════════════
    double CalculateDistance(double x1, double y1, double z1,
                              double x2, double y2, double z2);
    void SendDown(Ptr<Packet> pkt, 
              AquaSimAddress dst,
              double delay = 0);
    // ADD in protected section alongside other members:

// ════════════════════════════════════════════════════════
// Q-LEARNING DATA STRUCTURES
// ════════════════════════════════════════════════════════

// Q-table: key = (myNodeId, neighborId) → Q-value
// Each node maintains Q-values for each of its neighbors
using QKey = std::pair<uint32_t, uint32_t>;
// first  = state  (my node id)
// second = action (neighbor node id = next hop choice)
std::map<QKey, double> m_qTable;

// Q-learning hyperparameters
double m_alpha   = 0.3;   // learning rate
                           // how fast Q-values update
                           // 0=no learning, 1=overwrite
double m_gamma   = 0.7;   // discount factor
                           // how much future reward matters
                           // 0=greedy, 1=long-term
double m_epsilon = 0;   // exploration rate
                           // probability of random action
                           // instead of best known action

// Track last action taken per packet
// Key = (originalSrc, packetId)
// Value = neighbor chosen as next hop
using LastActionKey = std::pair<uint32_t, uint32_t>;
std::map<LastActionKey, uint32_t> m_lastAction;
// ADD in protected/public section:

struct OnOffState {
    bool   attacking       = false;
    double attackStartTime = 0.0;
    double attackDuration  = 30.0;
    double triggerProb     = 0.5;
    // 10% chance per packet to enter attack mode
};

// Per-node on-off state — non-static
// Each node instance has its OWN state
std::map<uint32_t, OnOffState> m_onOffState;

// Global switch to enable on-off attack on ALL nodes
static bool s_onOffEnabled;
static void EnableOnOffAttack() {
    s_onOffEnabled = true;
}
// ADD in protected section:
bool CheckOnOffAttack(uint32_t packetId);
// Q-learning functions
void   InitQValues(uint32_t neighborId);
double GetQValue(uint32_t neighborId);
void   UpdateQValue(uint32_t neighborId, double reward);
double ComputeReward(uint32_t neighborId,
                     bool     success,
                     double   actualDelay);
uint32_t SelectNextHopQL();   // Q-learning version
    
    void   DoDispose() override;
};

} // namespace ns3
#endif // AQUA_SIM_ROUTING_TBR_H
