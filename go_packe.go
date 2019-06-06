package main

import (
	"log"
	"os"

	"github.com/awalterschulze/gographviz"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
  	// The pcap[ng] file you want to visualize
	pf := "./file.pcap"

	// open file
	h, err := pcap.OpenOffline(pf)
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()

  	// extract the packet and remove duplication.
	flows := make(map[gopacket.Flow]int, 0)
	pSrc := gopacket.NewPacketSource(h, h.LinkType())
	for p := range pSrc.Packets() {
		if p.NetworkLayer() != nil {
			flows[p.NetworkLayer().NetworkFlow()]++
		}
	}

	// draw the directed graph.
	g := gographviz.NewGraph()
	if err := g.SetName("G"); err != nil {
		panic(err)
	}
	if err := g.SetDir(true); err != nil {
		panic(err)
	}
	if err := g.AddAttr("G", "bgcolor", "\"#343434\""); err != nil {
		panic(err)
	}
	if err := g.AddAttr("G", "layout", "circo"); err != nil {
		panic(err)
	}

	// configuration for nodes
	nodeAttrs := make(map[string]string)
	nodeAttrs["colorscheme"] = "rdylgn11"
	nodeAttrs["style"] = "\"solid,filled\""
	nodeAttrs["fontcolor"] = "6"
	nodeAttrs["fontname"] = "\"Migu 1M\""
	nodeAttrs["color"] = "7"
	nodeAttrs["fillcolor"] = "11"
	nodeAttrs["shape"] = "doublecircle"

	// make the nodes.
	nodes := make(map[string]bool)
	for f := range flows {
		if !nodes[f.Src().String()] {
			nodes[f.Src().String()] = true
		}
		if !nodes[f.Dst().String()] {
			nodes[f.Dst().String()] = true
		}
	}

	// add nodes to the graph "G"
	for n := range nodes {
		if err := g.AddNode("G", "\""+n+"\"", nodeAttrs); err != nil {
			panic(err)
		}
	}

	// configuration for edges
	edgeAttrs := make(map[string]string)
	edgeAttrs["color"] = "white"

	// connect the nodes
	for f := range flows {
		err := g.AddEdge("\""+f.Src().String()+"\"",
			"\""+f.Dst().String()+"\"", true, edgeAttrs)
		if err != nil {
			panic(err)
		}
	}
	s := g.String()
	file, err := os.Create(`./digraph.dot`)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	file.Write([]byte(s))

}
