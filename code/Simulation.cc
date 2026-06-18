/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * TBR Simulation - Modeled after VBF example
 *
 * TOPOLOGY (string along Z-axis):
 *
 *  SENDER (0, 0, 100)   ← generates packets (deepest)
 *     |
 *   Node0 (0, 0, 66)    ← intermediate forwarder
 *     |
 *   Node1 (0, 0, 33)    ← intermediate forwarder
 *     |
 *   SINK  (0, 0,  0)    ← destination (surface)
 *
 * PARAMETERS:
 *   - Range        : 40m
 *   - PacketSize   : 50 bytes
 *   - DataRate     : 400 bps
 *   - OnTime       : 1.0s
 *   - OffTime      : 5.0s
 *   - Hello phase  : staggered (sender=0s, node0=3s,
 *                               node1=6s, sink=9s)
 *   - Data start   : t=50s
 *   - Data stop    : t=100s
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/aqua-sim-ng-module.h"
#include "ns3/applications-module.h"
#include "ns3/log.h"
#include "ns3/callback.h"
#include <iomanip>
#include <cstdlib>   // rand()
#include <ctime>     // time()
//#include "aqua-sim-routing-tbr.h"
//#include "aqua-sim-mac-broadcast.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("TBR_Simulation");

// ════════════════════════════════════════════════════════════
// GLOBAL COUNTERS
// ════════════════════════════════════════════════════════════
//static uint32_t g_packetsSentBySource = 0;

// ════════════════════════════════════════════════════════════
// CALLBACK: fired every time OnOff app sends a packet
// ════════════════════════════════════════════════════════════
void AppSendTrace(Ptr<const Packet> packet)
{
    //g_packetsSentBySource++;
    std::cout << "[SOURCE TX] pkt#" << AquaSimTBR::GetPacketsAtSource()
              << " t="    << std::fixed << std::setprecision(4)
              << Simulator::Now().GetSeconds() << "s"
              << " UID="  << packet->GetUid()
              << " size=" << packet->GetSize() << "B\n";
}

// ════════════════════════════════════════════════════════════
// CALLBACK: PHY receive trace
// ════════════════════════════════════════════════════════════
void PhyRxTrace(std::string nodeLabel,
                Ptr<const Packet> packet)
{
    std::cout << "[PHY RX] " << nodeLabel
              << " t="    << std::fixed << std::setprecision(4)
              << Simulator::Now().GetSeconds() << "s"
              << " UID="  << packet->GetUid()
              << " size=" << packet->GetSize() << "B\n";
}

// ════════════════════════════════════════════════════════════
// CALLBACK: PHY transmit trace
// ════════════════════════════════════════════════════════════
void PhyTxTrace(std::string nodeLabel,
                Ptr<const Packet> packet)
{
    std::cout << "[PHY TX] " << nodeLabel
              << " t="    << std::fixed << std::setprecision(4)
              << Simulator::Now().GetSeconds() << "s"
              << " UID="  << packet->GetUid()
              << " size=" << packet->GetSize() << "B\n";
}

// ════════════════════════════════════════════════════════════
// TRIGGER HELLO
// Called by Simulator::Schedule to fire first hello
// on a specific TBR node at a scheduled time
// ════════════════════════════════════════════════════════════
void TriggerHello(Ptr<AquaSimTBR> tbrProto)
{
     // ensure TBR is initialized before sending hello
    tbrProto->SendHello();
}
// ════════════════════════════════════════════════════════════
// RANDOM SENDER ROTATION GLOBALS
// ════════════════════════════════════════════════════════════
static int                       g_currentSenderIdx = -1;
static double                    g_senderSlotDuration = 5.0;  // seconds
static ApplicationContainer      g_allSenderApps;
static int                       g_totalSenders = 6; // track recent senders
// ADD before main() alongside other globals:
static double g_simDataStop = 2500.0;  // matches simDataStop in main
// ── Pick a random sender index different from current ──
std::set<uint32_t> g_normalNodeIds;
std::set<uint32_t> g_dropNodeIds;
std::set<uint32_t> g_delayNodeIds;
std::set<uint32_t> g_broadcastNodeIds;
static double simDataStop = 2500.0; // default, can be overridden in main()
// ════════════════════════════════════════════════════════════
// MAIN
// ════════════════════════════════════════════════════════════
// ADD before main():
double totalEnergyConsumed = 0.0;
void PrintFinalEnergy(NodeContainer allNodes)
{
    std::cout << "\n================================================\n"
              << "  FINAL NODE ENERGY\n"
              << "================================================\n";
    double maxi=0;
    for (uint32_t i = 0; i < allNodes.GetN(); i++)
    {
        Ptr<Node> node = allNodes.Get(i);

        if (node->GetNDevices() == 0) continue;

        Ptr<AquaSimNetDevice> dev = nullptr;
        for (uint32_t d = 0; d < node->GetNDevices(); d++)
        {
            dev = DynamicCast<AquaSimNetDevice>(
                      node->GetDevice(d));
            if (dev) break;
        }

        if (!dev)            continue;
        if (!dev->EnergyModel()) continue;

        double remaining = dev->EnergyModel()->GetEnergy();
        double initial   = dev->EnergyModel()->GetInitialEnergy();
        double consumed  = initial - remaining;
        maxi = std::max(maxi, consumed);
        totalEnergyConsumed += consumed;
        double pct       = (initial > 0.0)
            ? (consumed / initial * 100.0) : 0.0;

        std::cout << "  Node[" << i << "]"
                  << " addr="      << dev->GetAddress()
                  << " initial="   << std::fixed
                                   << std::setprecision(4)
                                   << initial   << "J"
                  << " remaining=" << remaining << "J"
                  << " consumed="  << consumed  << "J"
                  << " ("
                  << std::setprecision(2)
                  << pct           << "%)\n";
    }
    std::cout << "  Max initial energy across nodes: "
              << std::fixed << std::setprecision(4)
              << maxi << "J\n";
    std::cout << "================================================\n";
}
void PrintQValueSnapshot()
{
    double t = Simulator::Now().GetSeconds();

    double qNormal    =
        AquaSimTBR::GetAverageQForNodes(g_normalNodeIds);
    double qDrop      =
        AquaSimTBR::GetAverageQForNodes(g_dropNodeIds);
    double qDelay     =
        AquaSimTBR::GetAverageQForNodes(g_delayNodeIds);
    double qBroadcast =
        AquaSimTBR::GetAverageQForNodes(g_broadcastNodeIds);
    // ── Ph values ──
    double phN  = AquaSimTBR::GetAveragePhForNodes(g_normalNodeIds);
    double phD  = AquaSimTBR::GetAveragePhForNodes(g_dropNodeIds);
    double phDl = AquaSimTBR::GetAveragePhForNodes(g_delayNodeIds);
    double phB  = AquaSimTBR::GetAveragePhForNodes(g_broadcastNodeIds);

    // ── TG values ──
    double tgN  = AquaSimTBR::GetAverageTGForNodes(g_normalNodeIds);
    double tgD  = AquaSimTBR::GetAverageTGForNodes(g_dropNodeIds);
    double tgDl = AquaSimTBR::GetAverageTGForNodes(g_delayNodeIds);
    double tgB  = AquaSimTBR::GetAverageTGForNodes(g_broadcastNodeIds);

    // ── TD values ──
    double tdN  = AquaSimTBR::GetAverageTDForNodes(g_normalNodeIds);
    double tdD  = AquaSimTBR::GetAverageTDForNodes(g_dropNodeIds);
    double tdDl = AquaSimTBR::GetAverageTDForNodes(g_delayNodeIds);
    double tdB  = AquaSimTBR::GetAverageTDForNodes(g_broadcastNodeIds);
    // ── Print to console ──
    std::cout << "[Q_SNAPSHOT] t=" << std::fixed
              << std::setprecision(0) << t << "s"
              << "  Normal="    << std::setprecision(4)
              << qNormal
              << "  Drop="      << qDrop
              << "  Delay="     << qDelay
              << "  Broadcast=" << qBroadcast
              << "\n";

    // ── Save into global array ──
    AquaSimTBR::StoreQSnapshot(
        t, qNormal, qDrop, qDelay, qBroadcast);
        AquaSimTBR::StorePhSnapshot(
        t,
        phN, phD, phDl, phB,
        tgN, tgD, tgDl, tgB,
        tdN, tdD, tdDl, tdB);
    if (t + 2000.0 <= simDataStop) {
        Simulator::Schedule(
            Seconds(2000.0),
            &PrintQValueSnapshot);
    }
}
int main(int argc, char *argv[])
{
    // ── Simulation parameters ──
//std::ofstream logFile("QL_thesis_brod_mixed.txt");
//std::streambuf* oldCout = std::cout.rdbuf();
//std::cout.rdbuf(logFile.rdbuf());
// From here ALL cout goes to file
 RngSeedManager::SetSeed(42);  // fixed seed
 RngSeedManager::SetRun(1);    // fixed run number
// ADD at very end of main() before return 0:

    //LogComponentEnable("AquaSimTBR",LOG_LEVEL_ALL);ttt
    //LogComponentEnable("AquaSimBroadcastMac",LOG_LEVEL_ALL);
    double   simDataStart  = 2000;   // hello phase ends, data begins
    simDataStop   = 30000;  // data phase ends
    double   simStop      = 30010;  // total simulation stop
   const int      numNodes      = 600;      // intermediate forwarder count
    const int      numSinks      = 50;
    const int      source_nodes   = 10;
    // ── Channel / PHY ──
    double   range         = 180;   // transmission range (m)
    int unique_nodes = numNodes + numSinks + source_nodes;
    // ── Traffic ──
    uint32_t m_dataRate    = 400;    // bps
    uint32_t m_packetSize  =   50;     // bytes
    double   onTime        = 4.001;    // seconds ON
    double   offTime       = 3;    // seconds OFF
    g_totalSenders=source_nodes; // set total senders for random rotation
    g_simDataStop = simDataStop; // set global for switch scheduling
    g_senderSlotDuration = onTime + offTime; // each sender active for one full cycle
    // ── TBR ──
    double   helloInterval = 10.0;   // periodic hello period (s)
    double   trustThresh   = 0.2;    // TG below this → suspect

    // ── Staggered hello times ──
    std :: vector<double> helloTimes;
    for(int i=0;i<numNodes+numSinks+source_nodes;i++)
    {
        helloTimes.push_back(2*i);  // stagger hellos every 2 seconds
    }


    CommandLine cmd;
    cmd.AddValue("simStop",  "Total sim time (s)", simStop);
    cmd.AddValue("range",    "Comm range (m)",     range);
    cmd.Parse(argc, argv);

    std::cout << "================================================\n"
              << "  TBR Underwater Simulation\n"
              << "  Hello phase    : t=0s  → t="
                                   << simDataStart << "s\n"
              << "  Data  phase    : t="   << simDataStart
              << "s → t="                  << simDataStop << "s\n"
              << "  Range          : "     << range        << "m\n"
              << "  PacketSize     : "     << m_packetSize << "B\n"
              << "  DataRate       : "     << m_dataRate   << "bps\n"
              << "  OnTime/OffTime : "     << onTime
              << "s / "                    << offTime      << "s\n"
              << "================================================\n";

    // ════════════════════════════════════════════════
    // NODE CONTAINERS
    // Exact same pattern as VBF example
    // ════════════════════════════════════════════════
    NodeContainer nodesCon;    // intermediate forwarders
    NodeContainer sinksCon;    // sink
    NodeContainer senderCon;   // source

    nodesCon.Create(numNodes);
    sinksCon.Create(numSinks);
    senderCon.Create(source_nodes);

    // PacketSocket on all nodes — required by AquaSim
    PacketSocketHelper socketHelper;
    socketHelper.Install(nodesCon);
    socketHelper.Install(sinksCon);
    socketHelper.Install(senderCon);

    // ════════════════════════════════════════════════
    // CHANNEL + AQUASIM HELPER
    // Exact same pattern as VBF example
    // ════════════════════════════════════════════════
    AquaSimChannelHelper channel = AquaSimChannelHelper::Default();

    channel.SetPropagation("ns3::AquaSimRangePropagation");

    AquaSimHelper asHelper = AquaSimHelper::Default();
    asHelper.SetChannel(channel.Create());

    // ── MAC: BroadcastMac (same as VBF) ──
    asHelper.SetMac("ns3::AquaSimBroadcastMac");

    // ── Routing: TBR instead of VBF ──
    asHelper.SetRouting("ns3::AquaSimTBR",
        "CommRange",      DoubleValue(range),
        "HelloInterval",  DoubleValue(helloInterval),
        "TrustThreshold", DoubleValue(trustThresh));

    // ════════════════════════════════════════════════
    // MOBILITY — static positions
    //
    // Depth increases with Z value:
    //   SENDER (0,0,100) ← deepest
    //   Node0  (0,0, 66) ← first relay
    //   Node1  (0,0, 33) ← second relay
    //   SINK   (0,0,  0) ← surface
    //
    // Each hop = 33m < range=40m  ✓
    // Non-adjacent nodes = 66m > range=40m ✗
    // Forces path: Sender→Node0→Node1→Sink
    // ════════════════════════════════════════════════
     MobilityHelper mobilitySender;
    Ptr<ListPositionAllocator> senderPos = CreateObject<ListPositionAllocator>();
    mobilitySender.SetPositionAllocator(
    "ns3::RandomBoxPositionAllocator",
    "X", StringValue("ns3::UniformRandomVariable[Min=0|Max=666]"),
    "Y", StringValue("ns3::UniformRandomVariable[Min=0|Max=666]"),
    "Z", StringValue("ns3::UniformRandomVariable[Min=980|Max=1000]")
);
    mobilitySender.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobilitySender.Install(senderCon);

    MobilityHelper mobilitySink;
    mobilitySink.SetPositionAllocator(
    "ns3::RandomBoxPositionAllocator",
    "X", StringValue("ns3::UniformRandomVariable[Min=0|Max=666]"),
    "Y", StringValue("ns3::UniformRandomVariable[Min=0|Max=666]"),
    "Z", StringValue("ns3::UniformRandomVariable[Min=0|Max=0]")
);
    mobilitySink.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobilitySink.Install(sinksCon);
    
    MobilityHelper mobilityNodes;
    mobilityNodes.SetPositionAllocator(
    "ns3::RandomBoxPositionAllocator",
    "X", StringValue("ns3::UniformRandomVariable[Min=0|Max=666]"),
    "Y", StringValue("ns3::UniformRandomVariable[Min=0|Max=666]"),
    "Z", StringValue("ns3::UniformRandomVariable[Min=1|Max=1000]")
);
    mobilityNodes.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobilityNodes.Install(nodesCon);
    

    // ════════════════════════════════════════════════
    // CREATE NET DEVICES
    // Exact same pattern as VBF example:
    //   devices[0]          = sender
    //   devices[1..N]       = intermediate nodes
    //   devices[N+1]        = sink
    // ════════════════════════════════════════════════
    NetDeviceContainer devices;

    std::cout << "\n--- Creating Devices ---\n";

    for(int i=0;i<source_nodes;i++)
    {
        Ptr<AquaSimNetDevice> dev = CreateObject<AquaSimNetDevice>();
        devices.Add(asHelper.Create(senderCon.Get(i), dev));
        dev->GetPhy()->SetTransRange(range);
        Ptr<AquaSimBroadcastMac> mac =DynamicCast<AquaSimBroadcastMac>(dev->GetMac());
        if (mac) mac->EnablePromiscuousMode();

        Ptr<MobilityModel> mob = senderCon.Get(i)->GetObject<MobilityModel>();
        Vector pos = mob->GetPosition();
        std::cout << "[SETUP] Sender   addr=" << dev->GetAddress()
                  << " pos=(" << pos.x << "," << pos.y << "," << pos.z << ")\n";
    }
    // ── Intermediate node devices ──
    for(int i=0;i<numNodes;i++)
    {
        Ptr<AquaSimNetDevice> dev = CreateObject<AquaSimNetDevice>();
        devices.Add(asHelper.Create(nodesCon.Get(i), dev));
        dev->GetPhy()->SetTransRange(range);
        Ptr<AquaSimBroadcastMac> mac =DynamicCast<AquaSimBroadcastMac>(dev->GetMac());
        if (mac) mac->EnablePromiscuousMode();

        Ptr<MobilityModel> mob = nodesCon.Get(i)->GetObject<MobilityModel>();
        Vector pos = mob->GetPosition();
        std::cout << "[SETUP] Nodes   addr=" << dev->GetAddress()
                  << " pos=(" << pos.x << "," << pos.y << "," << pos.z << ")\n";
    }

    // ── Sink device ──
    for(int i=0;i<numSinks;i++)
    {
        Ptr<AquaSimNetDevice> dev = CreateObject<AquaSimNetDevice>();
        devices.Add(asHelper.Create(sinksCon.Get(i), dev));
        dev->GetPhy()->SetTransRange(range);
        Ptr<AquaSimBroadcastMac> mac =DynamicCast<AquaSimBroadcastMac>(dev->GetMac());
        if (mac) mac->EnablePromiscuousMode();

        Ptr<MobilityModel> mob = sinksCon.Get(i)->GetObject<MobilityModel>();
        Vector pos = mob->GetPosition();
        std::cout << "[SETUP] Sink    addr=" << dev->GetAddress()
                  << " pos=(" << pos.x << "," << pos.y << "," << pos.z << ")\n";
    }
    for(int i=source_nodes+numNodes;i<numNodes+source_nodes+numSinks;i++)
{
    Ptr<AquaSimNetDevice> sinkDev =DynamicCast<AquaSimNetDevice>(devices.Get(i));

    uint32_t sinkId =AquaSimAddress::ConvertFrom(sinkDev->GetAddress()).GetAsInt();

    AquaSimTBR::AddSinkNode(sinkId);

    std::cout << "[SETUP] Registered sink node ID="
              << sinkId << "\n";
}
NodeContainer allNodes;
allNodes.Add(senderCon);
allNodes.Add(nodesCon);
allNodes.Add(sinksCon);
    // Helper lambda — get TBR pointer from device index
    auto GetTBR = [&](uint32_t idx) -> Ptr<AquaSimTBR>
    {
        Ptr<AquaSimNetDevice> dev =
            DynamicCast<AquaSimNetDevice>(
                devices.Get(idx));
        NS_ASSERT_MSG(dev,
            "Device " << idx << " is not AquaSimNetDevice");

        Ptr<AquaSimTBR> tbr =
            DynamicCast<AquaSimTBR>(dev->GetRouting());
        NS_ASSERT_MSG(tbr,
            "Routing on device " << idx
            << " is not AquaSimTBR");
        return tbr;
    };

    for(int i=0;i<numNodes+source_nodes+numSinks;i++)
    {
        Ptr<AquaSimTBR> tbr = GetTBR(i);
        tbr->DoInitialize();
    }
    std::cout << "\n[HELLO SCHEDULE]\n";
    for(int i=0;i<numNodes+source_nodes+numSinks;i++)
    {
        Ptr<AquaSimTBR> tbr = GetTBR(i);
        Simulator::Schedule(Seconds(helloTimes[i]),
            &TriggerHello, tbr);
        

    }
    


    // ════════════════════════════════════════════════
    // PHY TRACES — same as VBF example
    // ════════════════════════════════════════════════
    for (uint32_t i = 0; i < devices.GetN(); i++)
    {
        Ptr<AquaSimNetDevice> dev =
            DynamicCast<AquaSimNetDevice>(
                devices.Get(i));
        if (!dev) continue;

        std::string label = "addr="
            + std::to_string(
                AquaSimAddress::ConvertFrom(
                    dev->GetAddress()).GetAsInt());

        dev->GetPhy()->TraceConnectWithoutContext(
            "RxBegin",
            MakeBoundCallback(&PhyRxTrace, label));

        dev->GetPhy()->TraceConnectWithoutContext(
            "TxBegin",
            MakeBoundCallback(&PhyTxTrace, label));
    }

    // ════════════════════════════════════════════════
    // APPLICATION TRAFFIC
    // Exact same PacketSocket pattern as VBF example
    // Sink address = devices[numNodes+1]
    // ════════════════════════════════════════════════
    // Install ONE app per sender node, traces attached once
PacketSocketAddress socket;
socket.SetAllDevices();
socket.SetPhysicalAddress(
    devices.Get(numNodes + source_nodes)->GetAddress());
socket.SetProtocol(0);

// Each sender gets its OWN OnOffHelper with unique start/stop

double t = simDataStart;

while (t < simDataStop) {
    int idx=rand() % source_nodes; // pick random sender index
    

    double slotEnd = std::min(t + g_senderSlotDuration, simDataStop);

    OnOffHelper app("ns3::PacketSocketFactory", Address(socket));
    app.SetAttribute("OnTime",
        StringValue("ns3::ConstantRandomVariable[Constant=" +
                    std::to_string(onTime) + "]"));
    app.SetAttribute("OffTime",
        StringValue("ns3::ConstantRandomVariable[Constant=" +
                    std::to_string(offTime) + "]"));
    app.SetAttribute("DataRate",   DataRateValue(m_dataRate));
    app.SetAttribute("PacketSize", UintegerValue(m_packetSize));

    // KEY: install fresh app, immediately get its index
    uint32_t appIdx = senderCon.Get(idx)->GetNApplications(); // BEFORE install
    ApplicationContainer slotApp = app.Install(senderCon.Get(idx));
    slotApp.Start(Seconds(t));
    slotApp.Stop(Seconds(slotEnd+0.004));

    // Attach trace using captured appIdx — unique per slot
    Ptr<Application> thisApp = senderCon.Get(idx)->GetApplication(appIdx);
    thisApp->TraceConnectWithoutContext("Tx", MakeCallback(&AppSendTrace));

    std::cout << "[PLAN] slot t=" << t
              << "s → " << slotEnd
              << "s  sender idx=" << idx
              << "  appIdx=" << appIdx << "\n";

    t += g_senderSlotDuration+0.004; // add tiny epsilon to avoid overlap
}
    // ════════════════════════════════════════════════
    // SINK RECEIVE SOCKET
    // Exact same pattern as VBF example
    // ════════════════════════════════════════════════
    /*Ptr<Node>   sinkNode   = sinksCon.Get(0);
    TypeId      psfid      =
        TypeId::LookupByName(
            "ns3::PacketSocketFactory");
    Ptr<Socket> sinkSocket =
        Socket::CreateSocket(sinkNode, psfid);

    PacketSocketAddress sinkBindAddr;
    sinkBindAddr.SetAllDevices();
    sinkBindAddr.SetProtocol(0);
    sinkSocket->Bind(sinkBindAddr);*/

    // ════════════════════════════════════════════════
    // ASCII TRACE — same as VBF example
    // ════════════════════════════════════════════════
    int numMalicious = 60; // 10% of intermediate nodes are malicious
// Use NS-3 random variable for reproducible randomness
Ptr<UniformRandomVariable> randVar = CreateObject<UniformRandomVariable>();
randVar->SetAttribute("Min", DoubleValue(0));
randVar->SetAttribute("Max", DoubleValue(numNodes - 1));

std::set<int> maliciousIndices;

// Pick unique random indices until we have enough
while ((int)maliciousIndices.size() < numMalicious)
{
    int idx = (int)randVar->GetValue();
    maliciousIndices.insert(idx);
}

std::cout << "\n================================================\n"
          << "  MALICIOUS NODE ATTACK SETUP\n"
          << "================================================\n"
          << "  Total intermediate nodes : " << numNodes << "\n"
          << "  Malicious nodes (droppers): " << numMalicious
          << " (" << (numMalicious * 100 / numNodes) << "%)\n"
          << "  Malicious node addresses :\n";

for (int idx : maliciousIndices)
{
    Ptr<AquaSimNetDevice> dev = DynamicCast<AquaSimNetDevice>(
        nodesCon.Get(idx)->GetDevice(0));

    AquaSimAddress addr = AquaSimAddress::ConvertFrom(dev->GetAddress());

    // Register this node as malicious in VBF routing
    AquaSimTBR::AddMaliciousNode(addr);

    // Get position for display
    Ptr<MobilityModel> mob = nodesCon.Get(idx)->GetObject<MobilityModel>();
    Vector pos = mob->GetPosition();

    std::cout << "    [ATTACKER] Node[" << std::setw(3) << idx << "]"
              << "  addr=" << addr
              << "  pos=(" << std::fixed << std::setprecision(1)
              << pos.x << ", " << pos.y << ", " << pos.z << ")\n";
}
int numDelayAttackers = 60; // 10% of remaining nodes

Ptr<UniformRandomVariable> delayRandVar =
    CreateObject<UniformRandomVariable>();
delayRandVar->SetAttribute("Min", DoubleValue(0));
delayRandVar->SetAttribute("Max",
    DoubleValue(numNodes - 1));

std::set<int> delayIndices;

// Pick unique indices NOT already malicious
while ((int)delayIndices.size() < numDelayAttackers)
{
    int idx = (int)delayRandVar->GetValue();

    // Skip if already a packet dropper
    if (maliciousIndices.count(idx)) continue;

    delayIndices.insert(idx);
}

std::cout << "\n================================================\n"
          << "  DELAY ATTACK SETUP\n"
          << "================================================\n"
          << "  Total intermediate nodes  : " << numNodes  << "\n"
          << "  Delay attackers           : "
          << numDelayAttackers
          << " (" << (numDelayAttackers * 100 / numNodes)
          << "%)\n"
          << "  Delay attacker addresses  :\n";

for (int idx : delayIndices)
{
    Ptr<AquaSimNetDevice> dev =
        DynamicCast<AquaSimNetDevice>(
            nodesCon.Get(idx)->GetDevice(0));

    AquaSimAddress addr =
        AquaSimAddress::ConvertFrom(dev->GetAddress());

    AquaSimTBR::AddDelayAttacker(
        addr.GetAsInt());

    Ptr<MobilityModel> mob =
        nodesCon.Get(idx)->GetObject<MobilityModel>();
    Vector pos = mob->GetPosition();

    std::cout << "    [DELAY] Node[" << std::setw(3)
              << idx << "]"
              << "  addr=" << addr
              << "  pos=(" << std::fixed
                           << std::setprecision(1)
              << pos.x << ", "
              << pos.y << ", "
              << pos.z << ")\n";
}
int numBroadcastAttackers = 60; // 10% of nodes

Ptr<UniformRandomVariable> bcastRandVar =
    CreateObject<UniformRandomVariable>();
bcastRandVar->SetAttribute("Min", DoubleValue(0));
bcastRandVar->SetAttribute("Max",
    DoubleValue(numNodes - 1));

std::set<int> broadcastIndices;

// Pick unique indices NOT already in other attacks
while ((int)broadcastIndices.size()
       < numBroadcastAttackers)
{
    int idx = (int)bcastRandVar->GetValue();

    // Skip if already packet dropper
    if (maliciousIndices.count(idx))  continue;

    // Skip if already delay attacker
    if (delayIndices.count(idx))      continue;

    broadcastIndices.insert(idx);
}

std::cout << "\n================================================\n"
          << "  BROADCAST ATTACK SETUP\n"
          << "================================================\n"
          << "  Total intermediate nodes   : "
          << numNodes << "\n"
          << "  Broadcast attackers        : "
          << numBroadcastAttackers
          << " (" << (numBroadcastAttackers * 100
                      / numNodes) << "%)\n"
          << "  Repeat interval            : 2s\n"
          << "  Total repeat duration      : 50s\n"
          << "  Broadcast attacker addresses:\n";

for (int idx : broadcastIndices)
{
    Ptr<AquaSimNetDevice> dev =
        DynamicCast<AquaSimNetDevice>(
            nodesCon.Get(idx)->GetDevice(0));

    AquaSimAddress addr =
        AquaSimAddress::ConvertFrom(dev->GetAddress());

    AquaSimTBR::AddBroadcastAttacker(
        addr.GetAsInt());

    Ptr<MobilityModel> mob =
        nodesCon.Get(idx)->GetObject<MobilityModel>();
    Vector pos = mob->GetPosition();

    std::cout << "    [BCAST] Node[" << std::setw(3)
              << idx << "]"
              << "  addr=" << addr
              << "  pos=(" << std::fixed
                           << std::setprecision(1)
              << pos.x << ", "
              << pos.y << ", "
              << pos.z << ")\n";
}
std::cout << "================================================\n\n";
for (int i = 0; i < numNodes; i++) {
    Ptr<AquaSimNetDevice> dev =
        DynamicCast<AquaSimNetDevice>(
            nodesCon.Get(i)->GetDevice(0));
    uint32_t nodeId =
        AquaSimAddress::ConvertFrom(
            dev->GetAddress()).GetAsInt();

    bool isMal   = maliciousIndices.count(i)  > 0;
    bool isDelay = delayIndices.count(i)       > 0;
    bool isBcast = broadcastIndices.count(i)   > 0;

    if      (isMal)   g_dropNodeIds.insert(nodeId);
    else if (isDelay) g_delayNodeIds.insert(nodeId);
    else if (isBcast) g_broadcastNodeIds.insert(nodeId);
    else              g_normalNodeIds.insert(nodeId);
}

std::cout << "[Q_SNAPSHOT SETUP]"
          << "  normal="    << g_normalNodeIds.size()
          << "  drop="      << g_dropNodeIds.size()
          << "  delay="     << g_delayNodeIds.size()
          << "  broadcast=" << g_broadcastNodeIds.size()
          << "\n";

    // ════════════════════════════════════════════════
    // RUN
    // ════════════════════════════════════════════════
    Packet::EnablePrinting();

    std::cout << "\n================================================\n"
              << "  Simulation Starting\n"
              << "================================================\n\n";
    Simulator::Schedule(
    Seconds(simDataStop+6),
    &PrintFinalEnergy,
    allNodes);
    Simulator::Schedule(
    Seconds(2000.0),
    &PrintQValueSnapshot);
    Simulator::Stop(Seconds(simStop));
    Simulator::Run();

    // Channel counters — same as VBF example
    asHelper.GetChannel()->PrintCounters();

    Simulator::Destroy();
    
    // FINAL STATISTICS — same format as VBF example
    // ════════════════════════════════════════════════
    uint32_t atSink = AquaSimTBR::GetPacketsAtSink();
    uint32_t g_packetsSentBySource = AquaSimTBR::GetPacketsAtSource();

    double deliveryRatio = (g_packetsSentBySource > 0)
        ? (double)atSink / g_packetsSentBySource * 100.0
        : 0.0;

    std::cout << "\n================================================\n"
              << "  TBR SIMULATION RESULTS\n"
              << "================================================\n"
              << "  Packets sent by source  : "
                             << g_packetsSentBySource << "\n"
              << "  Packets received at sink: "
                             << atSink                << "\n"
              << "  Packet Delivery Ratio   : "
                             << std::fixed
                             << std::setprecision(2)
                             << deliveryRatio          << "%\n"
              << "  Packets lost            : "
                             << (g_packetsSentBySource - atSink)
                             << "\n"
              << "  Average E2E delay       : "
                             << AquaSimTBR::GetAverageDelay()
                             << "s\n"
                << "  Total energy consumed   : "
                             << std::fixed << std::setprecision(4)
                             << totalEnergyConsumed << "J\n"
                << " Energy per node  :"<< std::fixed << std::setprecision(4)
                             << (totalEnergyConsumed / allNodes.GetN())
                             << "J\n"
                <<"  Energy per packet : "
                             << std::fixed << std::setprecision(4)
                             << (g_packetsSentBySource > 0
                                 ? totalEnergyConsumed / atSink
                                 : 0.0) << "J" << "divided by total packets received at sink\n"
                <<"Effective energy per node per 100 packets : "
                             << std::fixed << std::setprecision(4)
                             << (g_packetsSentBySource > 0
                                 ? (totalEnergyConsumed / (atSink*allNodes.GetN()))*100
                                 : 0.0) << "J" << "\n"
                <<"packet drop attackers : " << numMalicious << "\n"
                <<"delay attackers : " << numDelayAttackers << "\n"
                <<"broadcast attackers : " << numBroadcastAttackers << "\n"
                <<"For QL_learning_mixed"<<"\n"
              << "================================================\n";
              // FIND in main() after Simulator::Destroy(), ADD:

// ── Print full Q-snapshot array ──
// Rows = time slots (t=2000 to t=30000, step 2000)
// Cols = Normal | Drop | Delay | Broadcast

const auto& snaps = AquaSimTBR::s_qSnapshots;

std::cout << "\n================================================\n"
          << "  Q-VALUE CONVERGENCE TABLE\n"
          << "  (avg Q of deeper node toward shallower neighbor)\n"
          << "  Only valid routing direction included (z_i > z_j)\n"
          << "================================================\n";

std::cout << std::left
          << std::setw(10) << "Time(s)"
          << std::setw(14) << "Normal"
          << std::setw(14) << "Packet Drop"
          << std::setw(14) << "Delay"
          << std::setw(14) << "Broadcast"
          << "\n";

std::cout << std::string(66, '-') << "\n";

for (const auto& s : snaps) {
    std::cout << std::fixed << std::setprecision(0)
              << std::setw(10) << s.simTime
              << std::setprecision(4)
              << std::setw(14) << s.avgNormal
              << std::setw(14) << s.avgDrop
              << std::setw(14) << s.avgDelay
              << std::setw(14) << s.avgBroadcast
              << "\n";
}

std::cout << "================================================\n"
          << "  Total snapshots: " << snaps.size() << "\n"
          << "================================================\n";
// ADD after Simulator::Destroy(), after Q table printout:

const auto& phSnaps = AquaSimTBR::s_phSnapshots;

// ── Column header helper ──
auto printHeader = [](const std::string& title) {
    std::cout << "\n================================================\n"
              << "  " << title << "\n"
              << "  (only z_i > z_j routing direction included)\n"
              << "================================================\n"
              << std::left
              << std::setw(10) << "Time(s)"
              << std::setw(14) << "Normal"
              << std::setw(14) << "Packet Drop"
              << std::setw(14) << "Delay"
              << std::setw(14) << "Broadcast"
              << "\n"
              << std::string(66,'-') << "\n";
};

// ── Ph table ──
printHeader("Ph-VALUE CONVERGENCE TABLE");
for (const auto& s : phSnaps) {
    std::cout << std::fixed << std::setprecision(0)
              << std::setw(10) << s.simTime
              << std::setprecision(4)
              << std::setw(14) << s.phNormal
              << std::setw(14) << s.phDrop
              << std::setw(14) << s.phDelay
              << std::setw(14) << s.phBroadcast
              << "\n";
}
std::cout << "================================================\n";

// ── TG table ──
printHeader("TG-VALUE CONVERGENCE TABLE");
for (const auto& s : phSnaps) {
    std::cout << std::fixed << std::setprecision(0)
              << std::setw(10) << s.simTime
              << std::setprecision(4)
              << std::setw(14) << s.tgNormal
              << std::setw(14) << s.tgDrop
              << std::setw(14) << s.tgDelay
              << std::setw(14) << s.tgBroadcast
              << "\n";
}
std::cout << "================================================\n";

// ── TD table ──
printHeader("TD-VALUE CONVERGENCE TABLE");
for (const auto& s : phSnaps) {
    std::cout << std::fixed << std::setprecision(0)
              << std::setw(10) << s.simTime
              << std::setprecision(4)
              << std::setw(14) << s.tdNormal
              << std::setw(14) << s.tdDrop
              << std::setw(14) << s.tdDelay
              << std::setw(14) << s.tdBroadcast
              << "\n";
}
std::cout << "================================================\n"
          << "  Total snapshots: " << phSnaps.size() << "\n"
          << "================================================\n";
//std::cout.rdbuf(oldCout);  // restore cout
//logFile.close();
    return 0;
}
/*```

---

## Why This Is Compatible With Your TBR Implementation
```
VBF pattern → TBR equivalent
─────────────────────────────────────────────────────────
asHelper.SetRouting(         asHelper.SetRouting(
  "ns3::AquaSimVBF",           "ns3::AquaSimTBR",
  "Width", 100,                "CommRange",      40,
  "TargetPos", ...)            "HelloInterval",  10,
                               "TrustThreshold", 0.2)

No hello needed in VBF    →  TriggerHello() scheduled
                              at t=0,3,6,9s before data

Broadcast dst always      →  MAC filters by dst address
                              promiscuous handles watchdog

AquaSimVBF::              →  AquaSimTBR::
  GetPacketsAtSink()            GetPacketsAtSink()
                                GetAverageDelay()
```

---

## Distance Check — Range 40m Covers Each Hop
```
Sender (z=100) → Node0 (z=66) = 34m < 40m ✓
Node0  (z=66)  → Node1 (z=33) = 33m < 40m ✓
Node1  (z=33)  → Sink  (z= 0) = 33m < 40m ✓

Sender → Node1 = 67m > 40m  ✗  (cannot skip Node0)
Sender → Sink  = 100m > 40m ✗  (cannot skip both)

TBR depth-based routing selects shallower nodes only
so path is forced: Sender→Node0→Node1→Sink*/
