#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("Exercise3Example");

int
main (int argc, char *argv[])
{
  double simTime = 10.0;           // simulation time in seconds
  std::string dataRate = "5Mbps";  // link capacity
  std::string delay    = "2ms";    // link delay

  CommandLine cmd;
  cmd.Parse (argc, argv);

  std::cout << "=== Exercise 3: Simple Point-to-Point UDP Simulation ===" << std::endl;
  std::cout << "Link data rate : " << dataRate << std::endl;
  std::cout << "Link delay     : " << delay << std::endl;
  std::cout << "Simulation time: " << simTime << " s" << std::endl;

  // 1. Create two nodes
  NodeContainer nodes;
  nodes.Create (2);

  // 2. Configure the point-to-point link
  PointToPointHelper pointToPoint;
  pointToPoint.SetDeviceAttribute ("DataRate", StringValue (dataRate));
  pointToPoint.SetChannelAttribute ("Delay", StringValue (delay));

  NetDeviceContainer devices = pointToPoint.Install (nodes);

  // 3. Install Internet stack
  InternetStackHelper stack;
  stack.Install (nodes);

  // 4. Assign IP addresses
  Ipv4AddressHelper address;
  address.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer interfaces = address.Assign (devices);

  // 5. Create a UDP packet sink on node 1 (receiver)
  uint16_t port = 9;
  Address sinkLocalAddress (InetSocketAddress (Ipv4Address::GetAny (), port));
  PacketSinkHelper packetSinkHelper ("ns3::UdpSocketFactory", sinkLocalAddress);
  ApplicationContainer sinkApp = packetSinkHelper.Install (nodes.Get (1));
  sinkApp.Start (Seconds (0.0));
  sinkApp.Stop (Seconds (simTime + 1));

  // 6. Create a UDP OnOff application on node 0 (sender)
  OnOffHelper onoff ("ns3::UdpSocketFactory",
                     InetSocketAddress (interfaces.GetAddress (1), port));
  onoff.SetConstantRate (DataRate ("1Mbps"), 1024); // 1 Mbps, 1024-byte packets
  ApplicationContainer clientApp = onoff.Install (nodes.Get (0));
  clientApp.Start (Seconds (1.0));        // start sending at t = 1s
  clientApp.Stop (Seconds (simTime));     // stop before simulation ends

  // 7. NetAnim XML output - MUST BE DECLARED BEFORE Simulator::Run()
  AnimationInterface anim ("exercise3.xml");
  
  // Enable packet metadata for detailed animation
  anim.EnablePacketMetadata (true);
  
  // Set node positions for visualization
  anim.SetConstantPosition (nodes.Get (0), 0.0, 0.0);
  anim.SetConstantPosition (nodes.Get (1), 50.0, 0.0);
  
  // (Optional) Set node descriptions
  anim.UpdateNodeDescription (nodes.Get (0), "Sender");
  anim.UpdateNodeDescription (nodes.Get (1), "Receiver");
  
  // (Optional) Set node colors
  anim.UpdateNodeColor (nodes.Get (0), 0, 255, 0);    // Green for sender
  anim.UpdateNodeColor (nodes.Get (1), 255, 0, 0);    // Red for receiver

  // (Optional) Enable IP counters if needed
  // anim.EnableIpv4L3ProtocolCounters (Seconds (0), Seconds (simTime));

  // (Optionnel) pcap pour Wireshark
  // pointToPoint.EnablePcapAll ("exercise3");

  // 8. Run the simulation
  Simulator::Stop (Seconds (simTime + 1));
  Simulator::Run ();

  // 9. After the simulation, compute some statistics
  Ptr<PacketSink> sink = DynamicCast<PacketSink> (sinkApp.Get (0));
  uint64_t totalBytes = sink->GetTotalRx ();
  double throughputMbps =
      (totalBytes * 8.0) / (simTime * 1000000.0); // Mbps

  std::cout << "\n=== Simulation Results ===" << std::endl;
  std::cout << "Total bytes received : " << totalBytes << " bytes" << std::endl;
  std::cout << "Average throughput   : " << throughputMbps << " Mbps" << std::endl;
  std::cout << "Simulation finished OK." << std::endl;
  std::cout << "NetAnim XML file created: exercise3.xml" << std::endl;

  Simulator::Destroy ();
  return 0;
}