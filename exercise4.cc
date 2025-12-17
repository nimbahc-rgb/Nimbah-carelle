/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
// Exercise 4 - Point-to-point link that goes DOWN then UP again.

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("Exercise4Example");

// Helper functions to bring a device link down / up
void
BringLinkDown (Ptr<PointToPointNetDevice> dev)
{
  dev->SetAttribute ("LinkDown", BooleanValue (true));
  std::cout << Simulator::Now ().GetSeconds ()
            << "s: link on this device is DOWN" << std::endl;
}

void
BringLinkUp (Ptr<PointToPointNetDevice> dev)
{
  dev->SetAttribute ("LinkDown", BooleanValue (false));
  std::cout << Simulator::Now ().GetSeconds ()
            << "s: link on this device is UP" << std::endl;
}

int
main (int argc, char *argv[])
{
  double simTime = 20.0; // seconds

  CommandLine cmd;
  cmd.Parse (argc, argv);

  std::cout << "=== Exercise 4: Link failure simulation ===" << std::endl;

  // Topology: n0 ---- n1 ---- n2
  NodeContainer nodes;
  nodes.Create (3);

  PointToPointHelper p2p;
  p2p.SetDeviceAttribute ("DataRate", StringValue ("5Mbps"));
  p2p.SetChannelAttribute ("Delay", StringValue ("2ms"));

  NodeContainer n0n1 (nodes.Get (0), nodes.Get (1));
  NodeContainer n1n2 (nodes.Get (1), nodes.Get (2));

  NetDeviceContainer d0d1 = p2p.Install (n0n1);
  NetDeviceContainer d1d2 = p2p.Install (n1n2);

  InternetStackHelper stack;
  stack.Install (nodes);

  Ipv4AddressHelper addr;
  addr.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i0i1 = addr.Assign (d0d1);

  addr.SetBase ("10.1.2.0", "255.255.255.0");
  Ipv4InterfaceContainer i1i2 = addr.Assign (d1d2);

  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  // UDP traffic from n0 -> n2
  uint16_t port = 10;
  PacketSinkHelper sinkHelper ("ns3::UdpSocketFactory",
                               InetSocketAddress (Ipv4Address::GetAny (), port));
  ApplicationContainer sinkApp = sinkHelper.Install (nodes.Get (2));
  sinkApp.Start (Seconds (0.0));
  sinkApp.Stop (Seconds (simTime + 1));

  OnOffHelper clientHelper ("ns3::UdpSocketFactory",
                            InetSocketAddress (i1i2.GetAddress (1), port));
  clientHelper.SetConstantRate (DataRate ("1Mbps"), 1024);
  ApplicationContainer clientApp = clientHelper.Install (nodes.Get (0));
  clientApp.Start (Seconds (1.0));
  clientApp.Stop (Seconds (simTime));

  // NetAnim - This line creates the XML file for NetAnim
  AnimationInterface anim ("exercise4.xml");
  anim.SetMaxPktsPerTraceFile (999999);
  anim.SetConstantPosition (nodes.Get (0), 0.0, 0.0);
  anim.SetConstantPosition (nodes.Get (1), 30.0, 0.0);
  anim.SetConstantPosition (nodes.Get (2), 60.0, 0.0);

  // Get the two devices of link n1--n2 (both ends)
  Ptr<PointToPointNetDevice> dev_n1 =
      DynamicCast<PointToPointNetDevice> (d1d2.Get (0));
  Ptr<PointToPointNetDevice> dev_n2 =
      DynamicCast<PointToPointNetDevice> (d1d2.Get (1));

  // Schedule link down at 6 s and up again at 12 s
  Simulator::Schedule (Seconds (6.0), &BringLinkDown, dev_n1);
  Simulator::Schedule (Seconds (6.0), &BringLinkDown, dev_n2);

  Simulator::Schedule (Seconds (12.0), &BringLinkUp, dev_n1);
  Simulator::Schedule (Seconds (12.0), &BringLinkUp, dev_n2);

  Simulator::Stop (Seconds (simTime + 1));
  Simulator::Run ();

  Ptr<PacketSink> sink = DynamicCast<PacketSink> (sinkApp.Get (0));
  uint64_t totalBytes = sink->GetTotalRx ();
  double throughputMbps =
      (totalBytes * 8.0) / (simTime * 1000000.0);

  std::cout << "\n=== Exercise 4 Results ===" << std::endl;
  std::cout << "Total bytes received : " << totalBytes << " bytes" << std::endl;
  std::cout << "Average throughput   : " << throughputMbps << " Mbps" << std::endl;
  std::cout << "NetAnim file created: exercise4.xml" << std::endl;

  Simulator::Destroy ();
  return 0;
}