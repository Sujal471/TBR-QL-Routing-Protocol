#include "aqua-sim-routing-tbr.h"
#include "aqua-sim-header.h"
#include "aqua-sim-address.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/mobility-model.h"
#include "ns3/double.h"
#include "ns3/uinteger.h"
#include <cmath>
#include <algorithm>
#include <limits>
using namespace ns3;

NS_LOG_COMPONENT_DEFINE("AquaSimTBR");
NS_OBJECT_ENSURE_REGISTERED(AquaSimTBR);

// ── Static member initialization ──
std::set<AquaSimAddress> AquaSimTBR::s_maliciousNodes;
// ADD alongside other static definitions:
std::set<uint32_t> AquaSimTBR::s_delayAttackers;
// ADD alongside other static definitions at top of file:
std::set<uint32_t> AquaSimTBR::s_sinkNodes;
// ADD alongside other static definitions:
std::set<uint32_t> AquaSimTBR::s_broadcastAttackers;
uint32_t AquaSimTBR::s_packetsAtSink = 0;
uint32_t AquaSimTBR::g_packetsSentBySource = 0; // initialize global source packet count
std::map<AquaSimTBR::SendTimeKey, double> AquaSimTBR::m_sendTime;
// ADD alongside other static definitions at top of file:
std::vector<AquaSimTBR*> AquaSimTBR::s_allInstances;
double   AquaSimTBR::s_totalDelay    = 0.0;
// ADD alongside other static definitions:
bool AquaSimTBR::s_onOffEnabled = true;
// ADD alongside other static definitions:
std::vector<AquaSimTBR::QSnapshot> AquaSimTBR::s_qSnapshots;
// ADD alongside other static definitions:
std::vector<AquaSimTBR::PhSnapshot> AquaSimTBR::s_phSnapshots;
// ═══════════════════════════════════════════════════════════
// TBRHeader — Serialize/Deserialize
// ═══════════════════════════════════════════════════════════

TypeId TBRHeader::GetTypeId() {
    static TypeId tid = TypeId("ns3::TBRHeader")
        .SetParent<Header>()
        .AddConstructor<TBRHeader>();
    return tid;
}
TypeId TBRHeader::GetInstanceTypeId() const { return GetTypeId(); }
void TBRHeader::Print(std::ostream &os) const {
    os << "TBRHeader[type=" << (int)msgType
       << " src=" << originalSrc
       << " id=" << packetId
       << " last=" << lastSender
       << " prev=" << prevSender << "]";
}
// Size: 1 + 4+4+4+4+4 + 8 + 8+8+8 + 8 + 4+8+8+4 = 89 bytes
uint32_t TBRHeader::GetSerializedSize() const { return 93; }

void TBRHeader::Serialize(Buffer::Iterator i) const {
    i.WriteU8(msgType);
    i.WriteU32(originalSrc);
    i.WriteU32(packetId);
    i.WriteU32(prevSender);
    i.WriteU32(lastSender);
    i.WriteU32(hopCount);
    // doubles — write as raw 8 bytes
    i.Write(reinterpret_cast<const uint8_t*>(&sendTimestamp), 8);
    i.Write(reinterpret_cast<const uint8_t*>(&senderX), 8);
    i.Write(reinterpret_cast<const uint8_t*>(&senderY), 8);
    i.Write(reinterpret_cast<const uint8_t*>(&senderZ), 8);
    i.Write(reinterpret_cast<const uint8_t*>(&senderEnergy), 8);
    i.WriteU32(aboutNodeId);
    i.Write(reinterpret_cast<const uint8_t*>(&oldTrust), 8);
    i.Write(reinterpret_cast<const uint8_t*>(&newTrust), 8);
    i.WriteU32(interactionCount);
}

uint32_t TBRHeader::Deserialize(Buffer::Iterator i) {
    msgType     = i.ReadU8();
    originalSrc = i.ReadU32();
    packetId    = i.ReadU32();
    prevSender  = i.ReadU32();
    lastSender  = i.ReadU32();
    hopCount    = i.ReadU32();
    i.Read(reinterpret_cast<uint8_t*>(&sendTimestamp), 8);
    i.Read(reinterpret_cast<uint8_t*>(&senderX), 8);
    i.Read(reinterpret_cast<uint8_t*>(&senderY), 8);
    i.Read(reinterpret_cast<uint8_t*>(&senderZ), 8);
    i.Read(reinterpret_cast<uint8_t*>(&senderEnergy), 8);
    aboutNodeId      = i.ReadU32();
    i.Read(reinterpret_cast<uint8_t*>(&oldTrust), 8);
    i.Read(reinterpret_cast<uint8_t*>(&newTrust), 8);
    interactionCount = i.ReadU32();
    return GetSerializedSize();
}

// ═══════════════════════════════════════════════════════════
// AquaSimTBR — Constructor and TypeId
// ═══════════════════════════════════════════════════════════

AquaSimTBR::AquaSimTBR()
  : m_commRange(40.0),
    m_lambda(0.2),
    m_sigma(0.5),
    m_trustThreshold(0.05),
    m_broadcastDelta(0.0005),
    m_helloInterval(10.0),
    m_watchdogTimeout(1.0),
    m_maxHops(30),
    m_myNodeId(0),
    m_packetCounter(0)
{
    m_rand = CreateObject<UniformRandomVariable>();
    
}

TypeId AquaSimTBR::GetTypeId() {
    static TypeId tid = TypeId("ns3::AquaSimTBR")
        .SetParent<AquaSimRouting>()
        .AddConstructor<AquaSimTBR>()
        .AddAttribute("CommRange",
            "Communication range in meters",
            DoubleValue(30.0),
            MakeDoubleAccessor(&AquaSimTBR::m_commRange),
            MakeDoubleChecker<double>())
        .AddAttribute("HelloInterval",
            "Hello packet interval in seconds",
            DoubleValue(10.0),
            MakeDoubleAccessor(&AquaSimTBR::m_helloInterval),
            MakeDoubleChecker<double>())
        .AddAttribute("TrustThreshold",
            "TG below this marks node as malicious",
            DoubleValue(0.3),
            MakeDoubleAccessor(&AquaSimTBR::m_trustThreshold),
            MakeDoubleChecker<double>());
    return tid;
}

int64_t AquaSimTBR::AssignStreams(int64_t stream) {
    m_rand->SetStream(stream);
    return 1;
}

// ═══════════════════════════════════════════════════════════
// DoInitialize — called by NS3 before simulation starts
// ═══════════════════════════════════════════════════════════

void AquaSimTBR::DoInitialize() {
    AquaSimRouting::DoInitialize();

    // Get my node ID from device address
    m_myNodeId = AquaSimAddress::ConvertFrom(
                     GetNetDevice()->GetAddress()).GetAsInt();
    AquaSimTBR::RegisterInstance(this);
    /*NS_LOG_INFO("TBR Node " << m_myNodeId << " initializing");
        std :: cout<<"TBR Node " << m_myNodeId << " initializing" << std :: endl;*/
    // Schedule first hello broadcast at t=0 with small random offset
    /*double offset = m_rand->GetValue() * 1.0;
    Simulator::Schedule(Seconds(offset),
                        &AquaSimTBR::SendHello, this);*/
}

// ═══════════════════════════════════════════════════════════
// RECV — Main entry point for all packets
// ═══════════════════════════════════════════════════════════

bool AquaSimTBR::Recv(Ptr<Packet> packet,
                       const Address &dest,
                       uint16_t protocolNumber)
{
    /*std ::cout<< "[RECV] TBR Node " << m_myNodeId
              << " received packet from " << dest
               << " protocol=" << protocolNumber << " at t=" << Simulator::Now().GetSeconds() << "energy"<<GetNetDevice()->EnergyModel()->GetEnergy() <<std ::endl;*/
    //NS_LOG_FUNCTION(this << m_myNodeId);

    AquaSimAddress myAddr =
        AquaSimAddress::ConvertFrom(GetNetDevice()->GetAddress());

    AquaSimHeader ash;
    packet->RemoveHeader(ash);
    // ── Downward packet — originated HERE ──f
    
    if (ash.GetDirection() == AquaSimHeader::DOWN) {
        g_packetsSentBySource++; // Increment global source packet count
        uint32_t nextHop = SelectNextHopQL();
        if (nextHop == 0) {
            NS_LOG_WARN("TBR Node " << m_myNodeId
                << " no valid next hop");
            return false;
        }

        TBRHeader hdr;
        hdr.msgType         = TBR_DATA;
        hdr.originalSrc     = m_myNodeId;
        hdr.packetId        = m_packetCounter++;
        hdr.prevSender      = 0;
        hdr.lastSender      = m_myNodeId;
        hdr.intendedNextHop = nextHop;
        hdr.hopCount        = 0;
        hdr.sendTimestamp   = Simulator::Now().GetSeconds();
        
        Ptr<MobilityModel> mob =
            GetNetDevice()->GetNode()->GetObject<MobilityModel>();
        Vector pos     = mob->GetPosition();
        hdr.senderX    = pos.x;
        hdr.senderY    = pos.y;
        hdr.senderZ    = pos.z;
        hdr.senderEnergy =
            GetNetDevice()->EnergyModel()->GetEnergy();
        m_sendTime[{hdr.originalSrc, hdr.packetId}] =
        Simulator::Now().GetSeconds();

        // ── SET DESTINATION TO NEXT HOP — not broadcast ──
        // MAC layer will reject this at all nodes except nextHop
        // BUT nodes running promiscuous will still overhear it
        AquaSimAddress nextHopAddr(nextHop);
        ash.SetSAddr(myAddr);
        ash.SetDAddr(nextHopAddr);       // ← unicast destination
        ash.SetDirection(AquaSimHeader::DOWN);
        ash.SetNumForwards(0);
        ash.SetOverheard(false);

        packet->AddHeader(hdr);
        packet->AddHeader(ash);

        
    // Only create watchdog for non-sink next hops
    // Sink is assumed to always receive successfully
    CreateWatchdog(hdr.packetId, hdr.originalSrc,
                   nextHop, hdr.sendTimestamp);

        NS_LOG_INFO("TBR Node " << m_myNodeId
            << " unicast pkt=" << hdr.packetId
            << " dst=" << nextHop<<"aqua-address:"<<nextHopAddr);

        SendDown(packet,AquaSimAddress(nextHop), 0);
        return true;
    }


    // ── Upward packet — received FROM channel ──
    TBRHeader hdr;
    if (!packet->PeekHeader(hdr)) {
        packet->AddHeader(ash);
        return false;
    }
    packet->RemoveHeader(hdr);
    

    uint32_t senderId = hdr.lastSender;
    /*std::cout<<"TBR Node " << m_myNodeId
              << " received pkt=" << hdr.packetId
              << " from=" << senderId
              << " type=" << (int)hdr.msgType
              << "\n" <<std ::endl;*/
    // ── Update neighbor's position and energy from any packet ──
    if (m_neighborTable.count(senderId)) {
        m_neighborTable[senderId].currentEnergy = hdr.senderEnergy;
        m_neighborTable[senderId].energyRatio =
            hdr.senderEnergy /
            m_neighborTable[senderId].initialEnergy;
        m_neighborTable[senderId].lastHeardTime =
            Simulator::Now().GetSeconds();
    }
    /*std::cout<<"TBR Node " << m_myNodeId
              << " updated neighbor " << senderId
              << " energy=" << hdr.senderEnergy
              << std ::endl;*/
              
    
//h
    
    // ── Route based on message type ──
    if (hdr.msgType == TBR_HELLO) {
        HandleHello(hdr, Simulator::Now().GetSeconds());
        return true;
    }
   
    if (hdr.msgType == TBR_TRUST_UPDATE) {
        HandleTrustUpdate(hdr);
        return true;
    }
    CheckRepeatTrust(hdr.originalSrc,
                 hdr.packetId,
                 hdr.lastSender);
    if (ash.GetOverheard()) {

        /*std::cout<<"TBR Node " << m_myNodeId
            << " overheard pkt=" << hdr.packetId
            << " from=" << hdr.lastSender
            << " running watchdog only" 
            <<"time"<< Simulator::Now().GetSeconds()
            <<"prev "<< hdr.prevSender
            << std ::endl;*/


        // Only run watchdog if WE are the upstream sender
        // i.e. we sent to hdr.lastSender previously
        if (hdr.prevSender == m_myNodeId) {
            CheckWatchdog(hdr);
        }

        // Discard — do not forward, do not count as received
        return false;
    }
     
    // ── DATA packet ──

    // Step 1: Check if WE are an upstream watchdog for this
    // i.e. hdr.prevSender == m_myNodeId means WE sent to
    // hdr.lastSender and now hdr.lastSender is forwarding
    /*if (hdr.prevSender == m_myNodeId) {
        CheckWatchdog(hdr);
    }*/

    // Step 2: Duplicate check
    auto pktSig = std::make_pair(hdr.originalSrc, hdr.packetId);
    if (m_seenPackets.count(pktSig)) {
        // Already processed — discard
        NS_LOG_INFO("TBR Node " << m_myNodeId
            << " duplicate pkt id=" << hdr.packetId << " dropped");
        return false;
    }
    m_seenPackets.insert(pktSig);

    // Step 3: Am I the sink (z=0)?
    Ptr<MobilityModel> mob =
        GetNetDevice()->GetNode()->GetObject<MobilityModel>();
    Vector myPos = mob->GetPosition();

    if (IsSink(m_myNodeId)) {
        // I am the sink — deliver

        DataForSink(packet, hdr);
        double now = Simulator::Now().GetSeconds();
    hdr.prevSender      = hdr.lastSender;
    hdr.lastSender      = m_myNodeId;
    hdr.intendedNextHop = SINK_ACK_NEXTHOP;
    hdr.hopCount       += 1;
    hdr.sendTimestamp   = now;
    hdr.senderX         = myPos.x;
    hdr.senderY         = myPos.y;
    hdr.senderZ         = myPos.z;
    hdr.senderEnergy    =
        GetNetDevice()->EnergyModel()->GetEnergy();

    // ── Unicast to next hop ──
    AquaSimAddress nextHopAddr(SINK_ACK_NEXTHOP);
    ash.SetDAddr(nextHopAddr);    // ← MAC will filter for us
    ash.SetSAddr(myAddr);
    ash.SetDirection(AquaSimHeader::DOWN);
    ash.SetNumForwards(ash.GetNumForwards() + 1);
    ash.SetOverheard(false);
    packet->AddHeader(hdr);
    packet->AddHeader(ash);
    SendDown(packet,AquaSimAddress(SINK_ACK_NEXTHOP), 0);
    return true;
    }

    // Step 4: Check hop count
    if (hdr.hopCount >= m_maxHops) {
        NS_LOG_WARN("TBR Node " << m_myNodeId
            << " max hops reached, dropping");
        return false;
    }
    // Step 5: Am I malicious? Drop and possibly replay
    //bool attacking_this_time=CheckOnOffAttack(hdr.packetId);
    bool attacking_this_time = true;
    if (IsMalicious(myAddr) && attacking_this_time) {
        std::cout << "TBR malicious node " << m_myNodeId
                  << " dropping packet " << hdr.packetId << std::endl;
        // Packet drop attack — just return false, no forward
        return false;
    }

    // Step 6: Select next hop and forward
    uint32_t nextHop = SelectNextHopQL();
    if (nextHop == 0) {
        NS_LOG_WARN("TBR Node " << m_myNodeId
            << " no valid next hop, dropping");
        return false;
    }

    double now = Simulator::Now().GetSeconds();
    hdr.prevSender      = hdr.lastSender;
    hdr.lastSender      = m_myNodeId;
    hdr.intendedNextHop = nextHop;
    hdr.hopCount       += 1;
    hdr.sendTimestamp   = now;
    hdr.senderX         = myPos.x;
    hdr.senderY         = myPos.y;
    hdr.senderZ         = myPos.z;
    hdr.senderEnergy    =
        GetNetDevice()->EnergyModel()->GetEnergy();

    // ── Unicast to next hop ──
    AquaSimAddress nextHopAddr(nextHop);
    ash.SetDAddr(nextHopAddr);    // ← MAC will filter for us
    ash.SetSAddr(myAddr);
    ash.SetDirection(AquaSimHeader::DOWN);
    ash.SetNumForwards(ash.GetNumForwards() + 1);
    ash.SetOverheard(false);

    //CreateWatchdog(hdr.packetId, hdr.originalSrc, nextHop, now);
    if (IsDelayAttacker(m_myNodeId) && attacking_this_time) {
        double backoff = 1.5 +
        ((m_rand->GetValue())*2.0);
        double sendTime = Simulator::Now().GetSeconds();

Simulator::Schedule(
    Seconds(backoff),
    &AquaSimTBR::DelayedForward,
    this,
    packet,
    ash,
    hdr,
    nextHop);

Simulator::Schedule(
    Seconds(backoff),
    &AquaSimTBR::CreateWatchdog,
    this,
    hdr.packetId,
    hdr.originalSrc,
    nextHop,
    sendTime + backoff);
// ↑ pass sendTime+backoff as sentTimestamp
//   so Tr is calculated from when packet
//   was actually sent not when attack started

return true; // Random backoff between 1.5 and 3.5 seconds
    }
    if (IsBroadcastAttacker(m_myNodeId) && attacking_this_time) {
         Ptr<Packet> copy = packet->Copy();
        Ptr<Packet> firstCopy = packet->Copy();
        firstCopy->AddHeader(hdr);
    firstCopy->AddHeader(ash);

    std::cout << "[BROADCAST ATTACK] Node=" << m_myNodeId
              << " first send pkt=" << hdr.packetId
              << " nextHop="        << nextHop
              << " t=" << Simulator::Now().GetSeconds()
              << "s will repeat 25 times every 2s\n";

    SendDown(firstCopy, AquaSimAddress(nextHop), 0);

    // ── Create normal watchdog for first send ──
    CreateWatchdog(hdr.packetId,
                   hdr.originalSrc,
                   nextHop,
                   Simulator::Now().GetSeconds());

    // ── Schedule 25 repeats every 2 seconds ──
    // 25 repeats × 2s = 50 seconds total
    int totalRepeats = 25;

    Simulator::Schedule(
        Seconds(2.0),
        &AquaSimTBR::RebroadcastPacket,
        this,
        packet,    // original — copy made inside
        hdr,       // header with correct chain fields
        nextHop,
        totalRepeats);

    return true;
    }
    // Only create watchdog for non-sink next hops
    // Sink is assumed to always receive successfully
    CreateWatchdog(hdr.packetId, hdr.originalSrc,
                   nextHop, now);
    packet->AddHeader(hdr);
    packet->AddHeader(ash);
    SendDown(packet,AquaSimAddress(nextHop), 0);
    return true;
}
void AquaSimTBR::SendSinkAck(uint32_t prevSenderNodeId)
{
    Ptr<MobilityModel> mob =
        GetNetDevice()->GetNode()
                      ->GetObject<MobilityModel>();
    Vector pos = mob->GetPosition();

    Ptr<Packet> ackPkt = Create<Packet>();

    TBRHeader hdr;
    hdr.msgType          = TBR_DATA;
    hdr.originalSrc      = m_myNodeId;
    hdr.packetId         = m_packetCounter++;
    hdr.prevSender       = prevSenderNodeId;
    hdr.lastSender       = m_myNodeId;
    hdr.intendedNextHop  = SINK_ACK_NEXTHOP; // 10000
    hdr.hopCount         = 0;
    hdr.sendTimestamp    = Simulator::Now().GetSeconds();
    hdr.senderX          = pos.x;
    hdr.senderY          = pos.y;
    hdr.senderZ          = pos.z;
    hdr.senderEnergy     =
        GetNetDevice()->EnergyModel()->GetEnergy();

    AquaSimHeader ash;
    ash.SetSAddr(AquaSimAddress::ConvertFrom(
                     GetNetDevice()->GetAddress()));

    // ── KEY CHANGE ──
    // dst=10000 means no real node accepts it normally
    // Every node hits PATH B in MAC → overheard=true
    // automatically without any extra code
    ash.SetDAddr(AquaSimAddress(SINK_ACK_NEXTHOP));

    ash.SetDirection(AquaSimHeader::DOWN);
    ash.SetNumForwards(1);
    ash.SetOverheard(false); // MAC will set this to true
                             // at every receiving node

    ackPkt->AddHeader(hdr);
    ackPkt->AddHeader(ash);

    /*std::cout << "[SINK ACK] sink="    << m_myNodeId
              << " prevSender="        << prevSenderNodeId
              << " dst=10000 (dummy)"
              << " t=" << Simulator::Now().GetSeconds()
              << "s\n";*/

    // Use base class SendDown directly with the dummy address
    // No need for broadcast — physical layer still
    // transmits to all neighbors in range
    Simulator::Schedule(
        Seconds(0),
        &AquaSimRouting::SendDown,
        this,
        ackPkt,
        AquaSimAddress(SINK_ACK_NEXTHOP),
        Seconds(0));
}
// ═══════════════════════════════════════════════════════════
// PHASE 1 — Hello / Discovery
// ═══════════════════════════════════════════════════════════

void AquaSimTBR::SendHello() {
    Ptr<MobilityModel> mob =
        GetNetDevice()->GetNode()->GetObject<MobilityModel>();
    Vector pos = mob->GetPosition();
    double energy = GetNetDevice()->EnergyModel()->GetEnergy();

    // Build hello packet
    Ptr<Packet> pkt = Create<Packet>();

    TBRHeader hdr;
    hdr.msgType      = TBR_HELLO;
    hdr.originalSrc  = m_myNodeId;
    hdr.lastSender   = m_myNodeId;
    hdr.prevSender   = 0;
    hdr.senderX      = pos.x;
    hdr.senderY      = pos.y;
    hdr.senderZ      = pos.z;
    hdr.senderEnergy = energy;
    hdr.sendTimestamp = Simulator::Now().GetSeconds();

    AquaSimHeader ash;
    ash.SetSAddr(AquaSimAddress::ConvertFrom(
                     GetNetDevice()->GetAddress()));
    ash.SetDAddr(AquaSimAddress::GetBroadcast());
    ash.SetDirection(AquaSimHeader::DOWN);
    ash.SetNumForwards(1);
    ash.SetOverheard(false);
    pkt->AddHeader(hdr);
    pkt->AddHeader(ash);

    SendDown(pkt, AquaSimAddress::GetBroadcast(), 0);

    /*std :: cout<<"TBR Node " << m_myNodeId
        << " sent hello at t="
        << Simulator::Now().GetSeconds()
        << " pos=(" << pos.x << "," << pos.y << "," << pos.z << ")"
        << " energy=" << energy << std::endl;*/

    // Reschedule next hello
    //Simulator::Schedule(Seconds(m_helloInterval),
                       // &AquaSimTBR::SendHello, this);
}

void AquaSimTBR::HandleHello(TBRHeader &hdr, double recvTime) {
    uint32_t senderId = hdr.lastSender;
    if (senderId == m_myNodeId) return; // my own hello reflected

    Ptr<MobilityModel> mob =
        GetNetDevice()->GetNode()->GetObject<MobilityModel>();
    Vector myPos = mob->GetPosition();

    double dist = CalculateDistance(
        myPos.x, myPos.y, myPos.z,
        hdr.senderX, hdr.senderY, hdr.senderZ);

    // Ignore if out of range
    //if (dist > m_commRange) return;

    bool isNew = (m_neighborTable.count(senderId) == 0);

    TBRNeighborEntry &entry = m_neighborTable[senderId];
    entry.nodeId        = senderId;
    entry.x             = hdr.senderX;
    entry.y             = hdr.senderY;
    entry.z             = hdr.senderZ;
    entry.distance      = dist;
    entry.currentEnergy = hdr.senderEnergy;
    entry.lastHeardTime = recvTime;
    entry.isAlive       = true;

    if (isNew) {
        // First time seeing this neighbor — set initial values
        entry.initialEnergy    = 10000;
        entry.energyRatio      = 1.0;
        entry.successfulPackets = 0;
        entry.droppedPackets    = 0;
        entry.Ts               = 0.5;
        entry.TD               = 0.5;
        entry.TG               = 0.5;
        entry.previousTD       = 0.5;
        entry.Te               = 1.0;
        NS_LOG_INFO("TBR Node " << m_myNodeId
            << " new neighbor " << senderId
            << " dist=" << dist
            << " z=" << hdr.senderZ);
    } 
        entry.energyRatio =
            hdr.senderEnergy / entry.initialEnergy;
    /*std ::cout<<"energy ratio updated for neighbor " << senderId
              << " energy=" << hdr.senderEnergy
              << " initialEnergy=" << entry.initialEnergy
              << " ratio=" << entry.energyRatio
              << std ::endl;*/

    // Recompute Ph for this neighbor
   /*std::cout<< "TBR Node " << m_myNodeId
              << " recomputing Ph for neighbor " << senderId
              << "\n" <<std ::endl;*/
    RecomputeInteractionTrust(senderId);
    RecomputeTG(senderId);
   std::cout<<ComputePh(senderId)<<std::endl;
   // FIND in HandleHello, at the end after ComputePh:
// ADD:
InitQValues(senderId);
}

// ═══════════════════════════════════════════════════════════
// ROUTING — Select Best Next Hop
// ═══════════════════════════════════════════════════════════

uint32_t AquaSimTBR::SelectNextHop() {
    Ptr<MobilityModel> mob =
        GetNetDevice()->GetNode()->GetObject<MobilityModel>();
    Vector myPos = mob->GetPosition();

    double   bestPh    = -std::numeric_limits<double>::infinity();
    uint32_t bestNode  = 0;
    /*std::cout<< "TBR Node " << m_myNodeId
              << " selecting next hop among "
              << m_neighborTable.size() << " neighbors"
              << "\n" <<std ::endl;*/
    for (auto &kv : m_neighborTable) {
        std::cout<< "TBR Node " << m_myNodeId
              << " evaluating neighbor " << kv.first
              << "\n" <<std ::endl;
        TBRNeighborEntry &entry = kv.second;

        // ── Depth constraint: next hop must be shallower ──
        // In this setup z=depth, lower z = closer to surface
        
        if (entry.z >= myPos.z) continue;

        // ── Must be alive ──
        if (!entry.isAlive) continue;

        // ── Must be above trust threshold ──
         double ph = ComputePh(entry.nodeId);
        /*std::cout<<"TBR Node " << m_myNodeId
            << " neighbor " << entry.nodeId
            << " Ph=" << entry.Ph
            << " TG=" << entry.TG
            << " energyRatio=" << entry.energyRatio<< std::endl;*/
        if (entry.TG < m_trustThreshold) {
            NS_LOG_INFO("TBR Node " << m_myNodeId
                << " skipping node " << entry.nodeId
                << " TG=" << entry.TG << " below threshold");
            continue;
        }
        
        // ── Recompute Ph ──

        if (ph > bestPh) {
            bestPh   = ph;
            bestNode = entry.nodeId;
        }
    }
    return bestNode; // 0 means no valid next hop found
}

// ═══════════════════════════════════════════════════════════
// WATCHDOG — Create, Check, Timeout
// ═══════════════════════════════════════════════════════════

void AquaSimTBR::CreateWatchdog(
    uint32_t packetId,
    uint32_t originalSrc,
    uint32_t sentToNode,
    double   sentTime)
{
    TBRWatchdogKey key = {packetId, originalSrc, sentToNode};

    TBRWatchdogEntry entry;
    entry.packetId          = packetId;
    entry.originalSrc       = originalSrc;
    entry.sentToNode        = sentToNode;
    entry.sentTimestamp     = sentTime;
    entry.theoreticalDelay  = ComputeTheoreticalDelay(sentToNode);
    entry.confirmed         = false;

    // Schedule timeout = m_watchdogTimeout × theoretical delay
    double timeout = 3.0 * entry.theoreticalDelay; // e.g. 3x expected delay
    // Minimum timeout of 3 seconds
    if (timeout < 3.0) timeout = 3.0;

    entry.timeoutEvent = Simulator::Schedule(
        Seconds(timeout),
        &AquaSimTBR::WatchdogTimeout,
        this,
        key);

    m_watchdogTable[key] = entry;
    DelayKey dKey = {originalSrc, packetId, sentToNode};
    m_sendDelayTime[dKey] = sentTime;
    

    NS_LOG_DEBUG("TBR Node " << m_myNodeId
        << " watchdog created for pkt=" << packetId
        << " sentTo=" << sentToNode
        << " timeout=" << timeout << "s");
}

void AquaSimTBR::CheckWatchdog(TBRHeader &hdr) {
    // Called when we overhear hdr.lastSender forwarding a packet
    // and hdr.prevSender == m_myNodeId
    // This means: the node we sent to (lastSender) forwarded it

    TBRWatchdogKey key = {
        hdr.packetId,
        hdr.originalSrc,
        hdr.lastSender   // the node we are watching
    };

    auto it = m_watchdogTable.find(key);
    if (it == m_watchdogTable.end()) {
        return; // No pending watchdog for this
    }

    TBRWatchdogEntry &entry = it->second;
    if (entry.confirmed) {
        return; // Already confirmed
    }

    // ── All checks passed — confirmed forwarding ──
   

    entry.timeoutEvent.Cancel();
    entry.confirmed = true;
    DelayKey dKey = {
        hdr.originalSrc,
        hdr.packetId,
        hdr.lastSender
    };
    double actualDelay =
        Simulator::Now().GetSeconds() - m_sendDelayTime[dKey];
    if (m_sendDelayTime.count(dKey)) {
        double theoreticalDelay =
            entry.theoreticalDelay;
             
        // Tr = theoretical / actual
        // If actual <= theoretical → Tr >= 1.0 → cap at 1.0
        // If actual >  theoretical → Tr <  1.0 → penalty
        double Tr = theoreticalDelay / actualDelay;
        Tr = std::min(Tr, 1.0); // cap at 1.0
        m_neighborTable[hdr.lastSender].Tr = Tr;
         m_sendDelayTime.erase(dKey);
    }

    std::cout<< "Check_watchdog" << "TBR Node " << m_myNodeId
        << " watchdog CONFIRMED for pkt=" << hdr.packetId
        << " forwarder=" << hdr.lastSender
        << " delay=" << actualDelay << "s"
        << " theoretical=" << entry.theoreticalDelay << "s";

    // Update trust — SUCCESS
    UpdateTrustOnSuccess(hdr.lastSender, actualDelay);
    double reward = ComputeReward(
    hdr.lastSender,
    true,          // success
    actualDelay);
UpdateQValue(hdr.lastSender, reward);

    m_watchdogTable.erase(it);
}

void AquaSimTBR::WatchdogTimeout(TBRWatchdogKey key) {
    auto it = m_watchdogTable.find(key);
    if (it == m_watchdogTable.end()) return;

    TBRWatchdogEntry &entry = it->second;
    if (entry.confirmed) {
        m_watchdogTable.erase(it);
        return;
    }

    uint32_t droppingNode = entry.sentToNode;
    double theoreticalDelay = entry.theoreticalDelay;
    double Tr = theoreticalDelay / 3.0;
    // = 1.0 / m_watchdogTimeout e.g. 1/2 = 0.5

    if (m_neighborTable.count(droppingNode)) {

        // On timeout Tr is penalized harder
        // no smoothing — direct assignment
        m_neighborTable[droppingNode].Tr = Tr;

        std::cout << "[DELAY TRUST] Node=" << m_myNodeId
                  << " TIMEOUT sender="    << droppingNode
                  << " theoretical="       << theoreticalDelay
                  << "s Tr="              << Tr
                  << " t=" << Simulator::Now().GetSeconds()
                  << "s\n";
    }

    // Clean up delay map entry
    DelayKey dKey = {
        entry.originalSrc,
        entry.packetId,
        droppingNode
    };
    m_sendDelayTime.erase(dKey);

    NS_LOG_WARN("TBR Node " << m_myNodeId
        << " watchdog TIMEOUT for pkt=" << entry.packetId<<"time:"<< Simulator::Now().GetSeconds()
        << " dropping node=" << droppingNode
        << " bij will be="
        << (m_neighborTable.count(droppingNode) ?
            m_neighborTable[droppingNode].droppedPackets + 1 : 1));

    // Update trust — DROP
    UpdateTrustOnDrop(droppingNode);
    // FIND in WatchdogTimeout, just before:
// UpdateTrustOnDrop(droppingNode);

// ADD before it:
double reward = ComputeReward(
    droppingNode,
    false,   // drop
    3.0);    // timeout duration as actual delay
UpdateQValue(droppingNode, reward);
    m_watchdogTable.erase(it);
}

// ═══════════════════════════════════════════════════════════
// TRUST COMPUTATION
// ═══════════════════════════════════════════════════════════

void AquaSimTBR::UpdateTrustOnSuccess(
    uint32_t neighborId,
    double   actualDelay)
{
    if (!m_neighborTable.count(neighborId)) return;

    TBRNeighborEntry &entry = m_neighborTable[neighborId];
    entry.successfulPackets += 1;

    RecomputeInteractionTrust(neighborId);
    RecomputeTG(neighborId);
    ComputePh(neighborId);

    // Check if trust changed enough to broadcast
    double delta = std::abs(entry.TD - entry.previousTD);
    if (delta > m_broadcastDelta) {
        Simulator::Schedule(
    Seconds(1.0),
    &AquaSimTBR::BroadcastTrustUpdate,
    this,
    neighborId,
    entry.previousTD,
    entry.TD);
        entry.previousTD = entry.TD;
    }
}

void AquaSimTBR::UpdateTrustOnDrop(uint32_t neighborId) {
    if (!m_neighborTable.count(neighborId)) return;

    TBRNeighborEntry &entry = m_neighborTable[neighborId];
    entry.droppedPackets += 1;

    RecomputeInteractionTrust(neighborId);
    RecomputeTG(neighborId);
    ComputePh(neighborId);

    // Drop events ALWAYS trigger broadcast (large trust change)
    double delta = std::abs(entry.TD - entry.previousTD);
    if (delta > m_broadcastDelta) {
        BroadcastTrustUpdate(neighborId,
                             entry.previousTD, entry.TD);
        entry.previousTD = entry.TD;
    }

    NS_LOG_WARN("TBR Node " << m_myNodeId
        << " DROP detected for node " << neighborId
        << " bij=" << entry.droppedPackets
        << " Ts="  << entry.Ts
        << " TG="  << entry.TG);
}
void AquaSimTBR::CheckRepeatTrust(
    uint32_t originalSrc,
    uint32_t packetId,
    uint32_t lastSender)
{
    RepeatKey key = {originalSrc, packetId, lastSender};

    m_repeatCount[key] += 1;
    uint32_t count = m_repeatCount[key];

    if (count <= 1) {
        // First time — normal, no penalty
        std ::cout<< "First time seeing pkt=" << packetId
             << " from sender=" << lastSender
             << " count=" << count << "\n";
        return;
    }

    if (!m_neighborTable.count(lastSender)) return;

    TBRNeighborEntry &entry =
        m_neighborTable[lastSender];

    // ── Reduce Te by penalty factor 1/count ──
    entry.Te       =  std::min(1.0 / (double)count, entry.Te);

    if (entry.Te < 0.0) entry.Te = 0.0;

    // ── Recompute TD = (Ts + Te) / 2 ──
    entry.TD = (entry.Ts + (2*entry.Te)+entry.Tr)/4.0;


    std::cout << "[REPEAT] Node=" << m_myNodeId
              << " repeat #"  << count
              << " src="      << originalSrc
              << " pktId="    << packetId
              << " sender="   << lastSender
              << " penalty=1/"<< count
              << " newTe="    << entry.Te
              << " Ts="       << entry.Ts
              << " newTD="    << entry.TD
              << " t=" << Simulator::Now().GetSeconds()
              << "s\n";

    // Recompute TG and Ph — no broadcast
    RecomputeTG(lastSender);
    ComputePh(lastSender);
    QKey qkey = {m_myNodeId, lastSender};
    if (!m_qTable.count(qkey)) {
        InitQValues(lastSender);
    }
    if (m_qTable.count(qkey)) {

        // Reward scales with current Te
        // Te = 1.0 (no repeats)  → reward = 0 (neutral)
        // Te = 0.5 (2 repeats)   → reward = -0.25
        // Te = 0.04 (25 repeats) → reward = -0.48
        // Formula: reward = Te - 0.5 scaled to [-0.5, 0]
        // so first repeat gives mild penalty,
        // sustained repeats give progressively worse penalty
        double repeatReward = entry.Te - 0.5;
        // clamp to [-0.5, 0] — never positive from repeats
        if (repeatReward > 0.0) repeatReward = 0.0;

        double currentQ = m_qTable[qkey];
        double maxNextQ = entry.TG;  // normalized [0,1]
        if (maxNextQ < 0.0) maxNextQ = 0.0;
        double effectiveAlpha = m_alpha;
    if (repeatReward < 0) {
    effectiveAlpha = 0.6;  // fast punishment
} else {
    effectiveAlpha = 0.1;  // slow recovery
}
        double newQ = currentQ
                    + effectiveAlpha
                    * (repeatReward
                       + m_gamma * maxNextQ
                       - currentQ);

        m_qTable[qkey] = newQ;

        std::cout << "[QL REPEAT UPDATE] Node=" << m_myNodeId
                  << " neighbor=" << lastSender
                  << " count="    << count
                  << " Te="       << entry.Te
                  << " reward="   << repeatReward
                  << " oldQ="     << currentQ
                  << " newQ="     << newQ
                  << "\n";
    }
    
}
void AquaSimTBR::RecomputeInteractionTrust(uint32_t neighborId) {
    TBRNeighborEntry &entry = m_neighborTable[neighborId];

    uint32_t aij = entry.successfulPackets;
    uint32_t bij = entry.droppedPackets;

    if (aij + bij == 0) {
        entry.Ts = 0.5;
    }
    else{

    // Ta = aij / (aij + bij)
    double Ta = (double)aij / (aij + bij);

    // delta penalty factor = 1 / (bij + 1)
    // This causes rapid collapse when drops accumulate
    double delta = 1.0 / (bij + 1);

    // Ts = delta * Ta
    entry.Ts = delta * Ta;
    }
    entry.TD = (entry.Ts+2*(entry.Te)+entry.Tr)/4.0; // Direct trust = Ts in this implementation

    std::cout << "TBR Node " << m_myNodeId<<"Time"<< Simulator::Now().GetSeconds()
              << " trust recomputed for " << neighborId
              << " aij=" << aij << " bij=" << bij
              << " Ts=" << entry.Ts 
              << " Tr=" << entry.Tr
              << " Te=" << entry.Te
              << " TD=" << entry.TD
              << std::endl;
}

double AquaSimTBR::ComputeIndirectTrust(uint32_t nodeId) {
    auto outer = m_indirectTrustTable.find(nodeId);
    if (outer == m_indirectTrustTable.end()) {
        return 0.0; // no recommendations yet
    }

    double sum   = 0.0;
    uint32_t count = 0;

    for (auto &kv : outer->second) {
        uint32_t recommender = kv.first;
        double   trustVal    = kv.second.trustValue;

        // Only use if recommender is also MY neighbor
        // (common neighbor requirement from paper)
        if (!m_neighborTable.count(recommender)) continue;

        // Only use non-default values
        // (recommender actually interacted with nodeId)
        TBRNeighborEntry &rec = m_neighborTable[recommender];
        /*if (rec.successfulPackets == 0 &&
            rec.droppedPackets    == 0 &&
            trustVal              == 0.5) continue;*/

        sum   += trustVal;
        count += 1;
    }

    if (count == 0) return 0.5;

    double TI = sum / count;
    m_TI[nodeId] = TI;
    return TI;
}

void AquaSimTBR::RecomputeTG(uint32_t neighborId) {
    TBRNeighborEntry &entry = m_neighborTable[neighborId];

    double TD = entry.TD;
    double TI = ComputeIndirectTrust(neighborId);

    // G = total interactions
    uint32_t G = entry.successfulPackets + entry.droppedPackets;

    // eta = 1/(G+2) — shrinks as interactions grow
    // so direct trust dominates over time
    double eta = 1.0 / (G + 2);

    entry.TG = TD + eta * TI;

    // Clamp to [0, 1]
    /*if (entry.TG > 1.0) entry.TG = 1.0;
    if (entry.TG < 0.0) entry.TG = 0.0;*/

    std::cout << "TBR Node " << m_myNodeId
              << " TG for " << neighborId
              << " TD=" << TD << " TI=" << TI
              << " eta=" << eta << " TG=" << entry.TG << std::endl;
}

double AquaSimTBR::ComputePh(uint32_t neighborId) {
    if (!m_neighborTable.count(neighborId)) return 0.0;

    TBRNeighborEntry &entry = m_neighborTable[neighborId];

    // Ph = 10 * [lambda*(Ej/E0) + (1-lambda)*TG] + sigma/Lij
    double energyRatio = entry.energyRatio;
    double TG          = entry.TG;
    double dist        = entry.distance;

    if (dist < 0.001) dist = 0.001; // avoid division by zero
    Ptr<MobilityModel> mob = GetNetDevice()->GetNode()->GetObject<MobilityModel>();
    Vector myPos = mob->GetPosition();

    double Ph = (10.0 * (m_lambda * energyRatio))
                      + ((1.0 - m_lambda) * TG)+ (m_sigma/ dist);

    entry.Ph = Ph;
    return Ph;
}

double AquaSimTBR::ComputeTheoreticalDelay(uint32_t neighborId) {
   // Placeholder: in real implementation, compute based on distance and speed of sound
    if (!m_neighborTable.count(neighborId)) return 5.0;

    double dist = m_neighborTable[neighborId].distance;
    double Vs   = 1500.0; // speed of sound in water (m/s)

    // Propagation delay
    double t_prop = dist / Vs;

    // Add 50% margin for processing + queuing
    return t_prop * 2 + 0.1;
}

// ═══════════════════════════════════════════════════════════
// TRUST BROADCAST
// ═══════════════════════════════════════════════════════════

void AquaSimTBR::BroadcastTrustUpdate(
    uint32_t aboutNodeId,
    double   oldTD,
    double   newTD)
{
    TBRNeighborEntry &entry = m_neighborTable[aboutNodeId];
    uint32_t G = entry.successfulPackets + entry.droppedPackets;

    Ptr<Packet> pkt = Create<Packet>();

    TBRHeader hdr;
    hdr.msgType          = TBR_TRUST_UPDATE;
    hdr.originalSrc      = m_myNodeId;   // broadcaster
    hdr.lastSender       = m_myNodeId;
    hdr.aboutNodeId      = aboutNodeId;  // whose trust changed
    hdr.oldTrust         = oldTD;
    hdr.newTrust         = newTD;
    hdr.interactionCount = G;
    hdr.sendTimestamp    = Simulator::Now().GetSeconds();

    // Fill my position so receivers know it is from a neighbor
    Ptr<MobilityModel> mob =
        GetNetDevice()->GetNode()->GetObject<MobilityModel>();
    Vector pos = mob->GetPosition();
    hdr.senderX      = pos.x;
    hdr.senderY      = pos.y;
    hdr.senderZ      = pos.z;
    hdr.senderEnergy =
        GetNetDevice()->EnergyModel()->GetEnergy();

    AquaSimHeader ash;
    ash.SetSAddr(AquaSimAddress::ConvertFrom(
                     GetNetDevice()->GetAddress()));
    ash.SetDAddr(AquaSimAddress::GetBroadcast());
    ash.SetDirection(AquaSimHeader::DOWN);
    ash.SetNumForwards(1);
    ash.SetOverheard(false);
    pkt->AddHeader(hdr);
    pkt->AddHeader(ash);

    SendDown(pkt, AquaSimAddress::GetBroadcast(), 0);

    /*std::cout << "TBR Node " << m_myNodeId
              << " broadcasting trust update"
              << " about=" << aboutNodeId
              << " old=" << oldTD << " new=" << newTD << std::endl;*/
}

void AquaSimTBR::HandleTrustUpdate(TBRHeader &hdr) {
    uint32_t senderId    = hdr.lastSender;   // who is broadcasting
    uint32_t aboutNodeId = hdr.aboutNodeId;  // whose trust changed
    double   newTrust    = hdr.newTrust;

    // ── Validity: sender must be my neighbor ──
    if (!m_neighborTable.count(senderId)) return;

    // ── Validity: aboutNode must also be my neighbor ──
    // (common neighbor requirement)
    if (!m_neighborTable.count(aboutNodeId)) return;

    // ── Update indirect trust table ──
    TBRIndirectEntry &rec =
        m_indirectTrustTable[aboutNodeId][senderId];
    rec.aboutNodeId       = aboutNodeId;
    rec.recommenderNodeId = senderId;
    rec.trustValue        = newTrust;
    rec.timestamp         = Simulator::Now().GetSeconds();

    // ── Recompute TI and TG for aboutNode ──
    RecomputeTG(aboutNodeId);
    ComputePh(aboutNodeId);

    NS_LOG_INFO("TBR Node " << m_myNodeId
        << " indirect trust updated"
        << " about=" << aboutNodeId
        << " from=" << senderId
        << " value=" << newTrust
        << " new TI=" << m_TI[aboutNodeId]
        << " new Ph=" << m_neighborTable[aboutNodeId].Ph);
}

// ═══════════════════════════════════════════════════════════
// SINK DELIVERY
// ═══════════════════════════════════════════════════════════

void AquaSimTBR::DataForSink(Ptr<Packet> pkt, TBRHeader &hdr) {
    

    double recvTime = Simulator::Now().GetSeconds();
    double delay    = 0.0;

    // Try to compute end-to-end delay
    // originalSrc is the source node, but we track by packetId
    // In a real setup, source embeds sendTime in header
    // Here we use our local m_sendTime if we are the source
    SendTimeKey stKey = {hdr.originalSrc, hdr.packetId};
    if (m_sendTime.count(stKey)) {
    delay = recvTime - m_sendTime[stKey];
    s_totalDelay += delay;

    m_sendTime.erase(stKey);
    s_packetsAtSink++;  // cleanup after use
}

    NS_LOG_INFO("TBR SINK received pkt="
        << hdr.packetId
        << " from src=" << hdr.originalSrc
        << " hops=" << hdr.hopCount
        << " delay=" << delay << "s"
        << " total=" << s_packetsAtSink);

    /*std::cout << "[TBR SINK] pkt=" << hdr.packetId
        << " src=" << hdr.originalSrc
        << " hops=" << hdr.hopCount
        << " delay=" << delay
        << " t=" << recvTime<<" id="
        <<m_myNodeId<<"energy:"<<GetNetDevice()->EnergyModel()->GetEnergy()<<std::endl;*/
    if (!SendUp(pkt)) {
        NS_LOG_WARN("TBR DataForSink: SendUp failed");
    }
}
// ADD new function:
void AquaSimTBR::DelayedForward(
    Ptr<Packet>  packet,
    AquaSimHeader ash,
    TBRHeader    hdr,
    uint32_t     nextHop)
{
    // This fires after backoff delay
    // Packet is now forwarded as normal
    // but Tr trust will be penalized because
    // actual delay >> theoretical delay

    Ptr<MobilityModel> mob =
        GetNetDevice()->GetNode()
                      ->GetObject<MobilityModel>();
    Vector myPos = mob->GetPosition();

    // Update header with current time
    // prevSender and lastSender already set
    // before this was scheduled
    hdr.sendTimestamp  = Simulator::Now().GetSeconds();
    hdr.senderEnergy   =
        GetNetDevice()->EnergyModel()->GetEnergy();

    ash.SetDirection(AquaSimHeader::DOWN);
    ash.SetNumForwards(ash.GetNumForwards() + 1);
    ash.SetOverheard(false);

    packet->AddHeader(hdr);
    packet->AddHeader(ash);

    std::cout << "[DELAY ATTACK] Node=" << m_myNodeId
              << " releasing delayed pkt="
              << hdr.packetId
              << " to nextHop=" << nextHop
              << " at t=" << Simulator::Now().GetSeconds()
              << "s\n";

    SendDown(packet,
             AquaSimAddress(nextHop), 0);
}
void AquaSimTBR::RebroadcastPacket(
    Ptr<Packet> packet,
    TBRHeader   hdr,
    uint32_t    nextHop,
    int         remaining)
{
    if (remaining <= 0) return;

    // ── Make fresh copy of packet ──
    Ptr<Packet> copy = packet->Copy();

    // ── Keep same header fields ──
    // same originalSrc, packetId, prevSender
    // so receiving nodes detect repeat via
    // {src, pktId, lastSender} key
    // and Te trust collapses for this attacker
    hdr.sendTimestamp =
        Simulator::Now().GetSeconds();
    hdr.senderEnergy  =
        GetNetDevice()->EnergyModel()->GetEnergy();

    AquaSimHeader ash;
    ash.SetSAddr(AquaSimAddress::ConvertFrom(
                     GetNetDevice()->GetAddress()));
    ash.SetDAddr(AquaSimAddress(nextHop));
    ash.SetDirection(AquaSimHeader::DOWN);
    ash.SetNumForwards(1);
    ash.SetOverheard(false);

    copy->AddHeader(hdr);
    copy->AddHeader(ash);

    std::cout << "[BROADCAST ATTACK] Node=" << m_myNodeId
              << " resending pkt="  << hdr.packetId
              << " remaining="      << remaining
              << " nextHop="        << nextHop
              << " t=" << Simulator::Now().GetSeconds()
              << "s\n";

    SendDown(copy, AquaSimAddress(nextHop), 0);

    // ── Schedule next rebroadcast ──
    Simulator::Schedule(
        Seconds(2.0),
        &AquaSimTBR::RebroadcastPacket,
        this,
        packet,
        hdr,
        nextHop,
        remaining - 1);
}

// ═══════════════════════════════════════════════════════════
// UTILITY
// ═══════════════════════════════════════════════════════════

double AquaSimTBR::CalculateDistance(
    double x1, double y1, double z1,
    double x2, double y2, double z2)
{
    double dx = x2 - x1;
    double dy = y2 - y1;
    double dz = z2 - z1;
    return std::sqrt(dx*dx + dy*dy + dz*dz);
}

void AquaSimTBR::SendDown(Ptr<Packet> pkt,
                           AquaSimAddress dst,
                           double delay) {
    Simulator::Schedule(
        Seconds(delay),
        &AquaSimRouting::SendDown,
        this,
        pkt,
        dst,          // ← uses whatever address caller passed
        Seconds(0));
}
// ADD this new function:
void AquaSimTBR::InitQValues(uint32_t neighborId) {
    QKey key = {m_myNodeId, neighborId};

    if (m_qTable.count(key)) return; // already initialized

    // Initial Q-value = Ph score as starting estimate
    // This seeds Q-table with domain knowledge
    // so exploration starts from a reasonable baseline
    // rather than zero
    double initialQ = ComputePh(neighborId);
    if (initialQ <= 0.0) initialQ = 0.1; // safety floor

    m_qTable[key] = initialQ;

    std::cout << "[QL INIT] Node=" << m_myNodeId
              << " neighbor="      << neighborId
              << " initialQ="      << initialQ
              << "\n";
}
double AquaSimTBR::GetQValue(uint32_t neighborId) {
    QKey key = {m_myNodeId, neighborId};

    if (!m_qTable.count(key)) {
        // Not yet initialized — init now
        InitQValues(neighborId);
    }
    return m_qTable[key];
}
double AquaSimTBR::ComputeReward(
    uint32_t neighborId,
    bool     success,
    double   actualDelay)
{
    if (!m_neighborTable.count(neighborId)) return -1.0;

    TBRNeighborEntry &entry = m_neighborTable[neighborId];

    if (!success) {
        // Packet was dropped — large negative reward
        // Scaled by how many drops this node has caused
        double penalty = -1.0
            * (1.0 + entry.droppedPackets * 0.1);
        std::cout << "[QL REWARD] Node=" << m_myNodeId
                  << " neighbor=" << neighborId
                  << " DROP reward=" << penalty << "\n";
        return penalty;
    }

    // ── Positive reward components ──

    // 1. Trust reward — higher TG = better reward
    //    Range: 0 to 1
    double trustReward = entry.TG;

    // 2. Energy reward — prefer nodes with more energy left
    //    Range: 0 to 1
    double energyReward = entry.energyRatio;

    // 3. Delay reward — faster delivery = better reward
    //    theoreticalDelay / actualDelay capped at 1.0
    double theoDelay = ComputeTheoreticalDelay(neighborId);
    double delayReward = 0.0;
    if (actualDelay > 0.0) {
        delayReward = std::min(theoDelay / actualDelay, 1.0);
    } else {
        delayReward = 1.0;
    }

    // 4. Depth reward — prefer nodes closer to surface
    //    Nodes with smaller z value are shallower
    Ptr<MobilityModel> mob =
        GetNetDevice()->GetNode()
                      ->GetObject<MobilityModel>();
    Vector myPos = mob->GetPosition();
    double depthGain = myPos.z - entry.z;
    // Normalize: assume max useful gain = commRange
    double depthReward = std::min(depthGain / m_commRange,
                                  1.0);

    // ── Weighted combination ──
    // Weights reflect importance in UWSN routing:
    // Trust most important, then energy, delay, depth
     double teReward = entry.Te;
    double reward = 0.5 * trustReward
                  + 0.1* energyReward
                  + 0.3 * delayReward
                  + 0.1 * depthReward;

    std::cout << "[QL REWARD] Node="    << m_myNodeId
              << " neighbor="           << neighborId
              << " trust="              << trustReward
              << " energy="             << energyReward
              << " delay="              << delayReward
              << " depth="              << depthReward
              << " total reward="       << reward
              << "\n";

    return reward;
}
void AquaSimTBR::UpdateQValue(
    uint32_t neighborId,
    double   reward)
{
    QKey key = {m_myNodeId, neighborId};

    // Initialize if not present
    if (!m_qTable.count(key)) {
        InitQValues(neighborId);
    }
    double currentQ = m_qTable[key];
    double maxNextQ = 0.0;
    if (m_neighborTable.count(neighborId)) {
        maxNextQ = m_neighborTable[neighborId].TG;
        if (maxNextQ < 0.0) maxNextQ = 0.0;
    }
    double effectiveAlpha = m_alpha;
    if (reward < 0) {
    effectiveAlpha = 0.6;  // fast punishment
    } else {
    effectiveAlpha = 0.1;  // slow recovery
    }
    // ── Bellman equation ──
    double newQ = currentQ
                + effectiveAlpha
                  * (reward + (m_gamma * maxNextQ)- currentQ);
    m_qTable[key] = newQ;
}
uint32_t AquaSimTBR::SelectNextHopQL() {
    Ptr<MobilityModel> mob =
        GetNetDevice()->GetNode()
                      ->GetObject<MobilityModel>();
    Vector myPos = mob->GetPosition();

    // ── Build list of valid candidate neighbors ──
    std::vector<uint32_t> candidates;

    for (auto &kv : m_neighborTable) {
        TBRNeighborEntry &entry = kv.second;

        // Must be shallower (closer to surface)
        if (entry.z >= myPos.z) continue;

        // Must be alive
        if (!entry.isAlive) continue;

        // Must be above trust threshold
        if (entry.TG < m_trustThreshold) continue;

        // Initialize Q-value if first time
        InitQValues(entry.nodeId);

        candidates.push_back(entry.nodeId);
    }

    if (candidates.empty()) return 0;

    // ── Epsilon-greedy action selection ──
    double roll = m_rand->GetValue(); // 0.0 to 1.0

    if (roll < m_epsilon) {
        // ── EXPLORE: pick a random valid neighbor ──
        uint32_t randIdx =
            (uint32_t)(m_rand->GetValue()
                       * candidates.size())
            % candidates.size();

        uint32_t chosen = candidates[randIdx];

        std::cout << "[QL EXPLORE] Node=" << m_myNodeId
                  << " random choice="    << chosen
                  << " epsilon="          << m_epsilon
                  << "\n";
        return chosen;
    }

    // ── EXPLOIT: pick neighbor with highest Q-value ──
    double   bestQ    = -std::numeric_limits<double>::infinity();
    uint32_t bestNode = 0;

    for (uint32_t neighborId : candidates) {
        double q = GetQValue(neighborId);

        std::cout << "[QL EXPLOIT] Node="  << m_myNodeId
                  << " neighbor="          << neighborId
                  << " Q="                 << q
                  << " TG="
                  << m_neighborTable[neighborId].TG
                  << "\n";

        if (q > bestQ) {
            bestQ    = q;
            bestNode = neighborId;
        }
    }

    std::cout << "[QL SELECT] Node=" << m_myNodeId
              << " chose="           << bestNode
              << " Q="               << bestQ
              << "\n";

    return bestNode;
}
// ADD new function:
bool AquaSimTBR::CheckOnOffAttack(uint32_t packetId)
{
    if (!s_onOffEnabled) return false;

    // Sinks and sources never attack
    if (IsSink(m_myNodeId))  return false;

    double now = Simulator::Now().GetSeconds();

    // Get or create state for this node
    OnOffState &state = m_onOffState[m_myNodeId];

    // ── If currently in attack phase ──
    
    if (state.attacking) {
        double elapsed = now - state.attackStartTime;

        if (elapsed >= state.attackDuration) {
            // Attack phase ended — return to normal
            state.attacking = false;

            std::cout << "[ON-OFF] Node=" << m_myNodeId
                      << " EXIT attack phase after "
                      << elapsed << "s"
                      << " t=" << now << "s\n";

            // Fall through — behave normally this packet
            
        }
        else{
        // Still in attack phase — drop packet
        std::cout << "[ON-OFF] Node=" << m_myNodeId
                  << " ATTACKING pkt=" << packetId
                  << " remaining="
                  << (state.attackDuration - elapsed)
                  << "s t=" << now << "s\n";
        return true;  // true = drop this packet
        }
    }

    // ── Not currently attacking ──
    // Randomly decide to START an attack phase
    double roll = m_rand->GetValue();

    if (roll < state.triggerProb) {
        // Enter attack phase
        state.attacking       = true;
        state.attackStartTime = now;

        std::cout << "[ON-OFF] Node=" << m_myNodeId
                  << " ENTER attack phase for "
                  << state.attackDuration << "s"
                  << " roll=" << roll
                  << " t="   << now << "s\n";

        // Drop this triggering packet too
        return true;
    }

    // Normal behavior — do not attack
    return false;
}
void AquaSimTBR::DoDispose() {
    // Cancel all pending watchdog timers
    for (auto &kv : m_watchdogTable) {
        kv.second.timeoutEvent.Cancel();
    }
    m_watchdogTable.clear();
    m_rand = 0;
    AquaSimRouting::DoDispose();
}
