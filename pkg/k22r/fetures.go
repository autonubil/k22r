package k22r

import (
	"log"
	"net"

	"github.com/CN-TU/go-flows/flows"
	"github.com/CN-TU/go-flows/modules/features"
	"github.com/CN-TU/go-flows/packet"
	"github.com/CN-TU/go-ipfix"
	"github.com/google/gopacket/layers"
	"github.com/vishvananda/netlink"
)

////////////////////////////////////////////////////////////////////////////////

type octetDeltaCountPacket struct {
	flows.BaseFeature
	count int
}

func (f *octetDeltaCountPacket) Start(context *flows.EventContext) {
	f.BaseFeature.Start(context)
	f.count = 0
}

func (f *octetDeltaCountPacket) Stop(reason flows.FlowEndReason, context *flows.EventContext) {
	f.SetValue(f.count, context, f)
}

func (f *octetDeltaCountPacket) Event(new interface{}, context *flows.EventContext, src interface{}) {
	f.count += new.(packet.Buffer).NetworkLayerLength()
}

type packetDeltaCountPacket struct {
	flows.BaseFeature
	count uint64
}

func (f *packetDeltaCountPacket) Event(new interface{}, context *flows.EventContext, src interface{}) {
	f.count++
}

func (f *packetDeltaCountPacket) Start(context *flows.EventContext) {
	f.BaseFeature.Start(context)
	f.count = 0
}

func (f *packetDeltaCountPacket) Stop(reason flows.FlowEndReason, context *flows.EventContext) {
	f.SetValue(f.count, context, f)
}

// uint64Feature (basically interface ID)
type uint64Feature struct {
	flows.BaseFeature
	value uint64
}

func (f *uint64Feature) Stop(reason flows.FlowEndReason, context *flows.EventContext) {
	f.SetValue(f.value, context, f)
}

func (f *uint64Feature) IsConstant() bool {
	return true
}

// interfaceNameFeature
type stringFeature struct {
	flows.BaseFeature
	value string
}

func (f *stringFeature) Stop(reason flows.FlowEndReason, context *flows.EventContext) {
	f.SetValue(f.value, context, f)
}

func (f *stringFeature) IsConstant() bool {
	return true
}

func registerStringFeature(feature, value string) string {
	ie, err := ipfix.GetInformationElement(feature)
	if err != nil {
		log.Panic(err)
	}
	ie = ipfix.InformationElement{
		Name:   feature,
		Pen:    ie.Pen,
		ID:     ie.ID,
		Type:   ie.Type,
		Length: ie.Length,
	}

	flows.RegisterFeature(ie, feature, flows.FlowFeature, func() flows.Feature { return &stringFeature{value: value} }, flows.RawPacket)
	return feature
}

func registerUint64Feature(feature string, value uint64) string {
	ie, err := ipfix.GetInformationElement(feature)
	if err != nil {
		log.Panic(err)
	}
	ie = ipfix.InformationElement{
		Name:   feature,
		Pen:    ie.Pen,
		ID:     ie.ID,
		Type:   ie.Type,
		Length: ie.Length,
	}

	flows.RegisterFeature(ie, feature, flows.FlowFeature, func() flows.Feature { return &uint64Feature{value: value} }, flows.RawPacket)
	return feature
}

type tcpOptions struct {
	flows.BaseFeature
}

/*
CP options in packets of this Flow. The information is encoded in a set of bit fields.
For each TCP option, there is a bit in this set. The bit is set to 1 if any observed packet of this Flow contains the corresponding TCP option.
Otherwise, if no observed packet of this Flow contains the respective TCP option, the value of the corresponding bit is 0.

Options are mapped to bits according to their option numbers. TCP option Kind 0 corresponds to the least-significant bit in the tcpOptionsFull IE while Kind 255 corresponds to the most-significant bit of the IE.
This approach allows an observer to export any observed TCP option even if it does support that option and without requiring updating a mapping table.

The value of tcpOptionsFull IE may be encoded in fewer octets per the guidelines in Section 6.2 of [RFC7011].

The presence of tcpSharedOptionExID16List or tcpSharedOptionExID32List IEs is an indication that a shared TCP option (Kind=253 or 254) is observed in a Flow.
The presence of tcpSharedOptionExID16List or tcpSharedOptionExID32List IEs takes precedence over setting the corresponding bits in the tcpOptionsFull IE for the same Flow.
In order to optimize the use of the reduced-size encoding in the presence of tcpSharedOptionExID16List or tcpSharedOptionExID32List IEs,
the Exporter MUST NOT set to 1 the shared TCP options (Kind=253 or 254) flags of the tcpOptionsFull IE that is reported for the same Flow.

	ptions are mapped to bits according to their option numbers. Option number X is mapped to bit X.

TCP option numbers are maintained by IANA.
*/
func (f *tcpOptions) Event(new interface{}, context *flows.EventContext, src interface{}) {
	tcp := features.GetTCP(new)
	if tcp == nil {
		return
	}
	var val uint64
	raw := f.Value()
	if raw != nil {
		val = raw.(uint64)
	}
	for _, opt := range tcp.Options {
		optId := uint64(opt.OptionType)
		val |= (1 << (65 - optId))
	}
	f.SetValue(val, context, f)
}

////////////////////////////////////////////////////////////////////////////////

type tcpControlBits struct {
	flows.BaseFeature
}

func (f *tcpControlBits) Event(new interface{}, context *flows.EventContext, src interface{}) {
	var value uint16
	tcp := features.GetTCP(new)
	if tcp == nil {
		return
	}
	if tcp.FIN {
		value += 1 << 0
	}
	if tcp.SYN {
		value += 1 << 1
	}
	if tcp.RST {
		value += 1 << 2
	}
	if tcp.PSH {
		value += 1 << 3
	}
	if tcp.ACK {
		value += 1 << 4
	}
	if tcp.URG {
		value += 1 << 5
	}
	if tcp.ECE {
		value += 1 << 6
	}
	if tcp.CWR {
		value += 1 << 7
	}
	if tcp.NS {
		value += 1 << 8
	}

	raw := f.Value()
	if raw != nil {
		val := raw.(uint16)
		f.SetValue(value|val, context, f)
	} else {
		f.SetValue(value, context, f)
	}
}

////////////////////////////////////////////////////////////////////////////////

const EVT_FIN = 1
const EVT_ACK = 2

type tcpConnectionClosed struct {
	flows.BaseFeature
	history []byte
	pos     int
}

func (f *tcpConnectionClosed) Event(new interface{}, context *flows.EventContext, src interface{}) {
	tcp := features.GetTCP(new)
	if tcp == nil {
		return
	}

	// server SYN-ACK response - the opposite of what we are looking for
	if tcp.SYN && tcp.ACK {
		return
	}

	if tcp.RST {
		context.Flow().EOF(context)
	}

	if tcp.FIN {
		if f.pos != 0 && f.pos != 2 {
			f.pos = 0
		}
		f.history[f.pos] = EVT_FIN
		f.pos++
	}
	if tcp.ACK {
		if f.pos == 0 || f.pos == 2 {
			f.pos = 0
			return
		}
		f.history[f.pos] = EVT_ACK
		f.pos++
	}
	if f.pos > 3 {
		context.Flow().Export(flows.FlowEndReasonEnd, context, context.When())
	}
}

////////////////////////////////////////////////////////////////////////////////

type interfaceInfo struct {
	name  string
	vlan  int
	index int
}

type interfaceProperty struct {
	flows.BaseFeature
	resolved bool
	typ      InterfacePropertyType
	byMac    map[string]*interfaceInfo
}

type InterfacePropertyType int

const (
	_ InterfacePropertyType = iota
	InterfacePropertyTypeName
	InterfacePropertyTypeVLAN
	InterfacePropertyTypeIndex
)

func newInterfaceProperty(typ InterfacePropertyType) flows.Feature {
	f := &interfaceProperty{
		typ:   typ,
		byMac: make(map[string]*interfaceInfo),
	}
	f.init()
	return f
}
func (f *interfaceProperty) init() error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, iface := range interfaces {
		if len(iface.HardwareAddr) == 0 {
			continue
		}
		if iface.Flags != iface.Flags|net.FlagUp {
			continue
		}
		info := interfaceInfo{
			name:  iface.Name,
			index: iface.Index,
		}
		link, err := netlink.LinkByName(iface.Name)
		if err == nil {
			vlanLinks, err := netlink.LinkList()
			if err == nil {
				for _, vlanLink := range vlanLinks {
					// Type assertion to check if the link is a VLAN link
					vlan, ok := vlanLink.(*netlink.Vlan)
					if ok && vlan.ParentIndex == link.Attrs().Index {
						info.vlan = vlan.VlanId
					}
				}
			}
		}
		f.byMac[string(iface.HardwareAddr)] = &info
	}
	return nil
}

func (f *interfaceProperty) Start(ctx *flows.EventContext) {
	f.BaseFeature.Start(ctx)
	f.resolved = false
}

func (f *interfaceProperty) Event(new interface{}, context *flows.EventContext, src interface{}) {
	if f.resolved {
		return
	}
	f.resolved = true
	if eth, ok := new.(packet.Buffer).LinkLayer().(*layers.Ethernet); ok {
		var inf *interfaceInfo
		var ok bool
		if inf, ok = f.byMac[string(eth.SrcMAC)]; !ok {
			if inf, ok = f.byMac[string(eth.DstMAC)]; !ok {
				return
			}
		}
		switch f.typ {
		case InterfacePropertyTypeName:
			f.SetValue(inf.name, context, f)
		case InterfacePropertyTypeIndex:
			f.SetValue(uint64(inf.index), context, f)
		case InterfacePropertyTypeVLAN:
			if inf.vlan != 0 {
				f.SetValue(uint64(inf.vlan), context, f)
			}
		}
	}
}

/////////////

type paddingProperty struct {
	flows.BaseFeature
	resolved bool
}

func newPaddingProperty() flows.Feature {
	f := &paddingProperty{}
	f.init()
	return f
}
func (f *paddingProperty) init() error {

	return nil
}

func (f *paddingProperty) Start(ctx *flows.EventContext) {
	f.BaseFeature.Start(ctx)
	f.resolved = false
}

func (f *paddingProperty) Event(new interface{}, context *flows.EventContext, src interface{}) {
	if f.resolved {
		return
	}
	f.resolved = true
}

func init() {
	flows.RegisterStandardFeature("tcpControlBits", flows.FlowFeature, func() flows.Feature { return &tcpControlBits{} }, flows.RawPacket)
	flows.RegisterStandardFeature("packetDeltaCount", flows.FlowFeature, func() flows.Feature { return &packetDeltaCountPacket{} }, flows.RawPacket)
	flows.RegisterStandardFeature("octetDeltaCount", flows.FlowFeature, func() flows.Feature { return &octetDeltaCountPacket{} }, flows.RawPacket)
	flows.RegisterStandardFeature("tcpOptions", flows.FlowFeature, func() flows.Feature { return &tcpOptions{} }, flows.RawPacket)
	flows.RegisterStandardFeature("interfaceName", flows.FlowFeature, func() flows.Feature { return newInterfaceProperty(InterfacePropertyTypeName) }, flows.RawPacket)
	flows.RegisterStandardFeature("ingressInterface", flows.FlowFeature, func() flows.Feature { return newInterfaceProperty(InterfacePropertyTypeIndex) }, flows.RawPacket)
	flows.RegisterStandardFeature("vlanId", flows.FlowFeature, func() flows.Feature { return newInterfaceProperty(InterfacePropertyTypeVLAN) }, flows.RawPacket)

	flows.RegisterControlFeature("_tcpConnectionClosed", "abort flow if tcp connection is done", func() flows.Feature { return &tcpConnectionClosed{pos: 0, history: make([]byte, 4)} })

	flows.RegisterStandardFeature("paddingOctets", flows.FlowFeature, func() flows.Feature { return newPaddingProperty() }, flows.RawPacket)

}

// TODO:
// bgpNextHopIPv4Address
// bgpNextHopIPv6Address
