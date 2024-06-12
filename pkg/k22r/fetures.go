package k22r

import (
	"log"

	"github.com/CN-TU/go-flows/flows"
	"github.com/CN-TU/go-flows/packet"
	"github.com/CN-TU/go-ipfix"
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

func init() {
	// flows.RegisterCustomFunction("const", "returns the first arg as const", resolveConst, flows.FlowFeature, func() flows.Feature { return &constant{} }, flows.Const)
	// flows.RegisterTypedFunction("interfaceName", "interface name", ipfix.StringType, 0, flows.FlowFeature, func() flows.Feature { return &interfaceNameFeature{} }, flows.Const)

	flows.RegisterStandardFeature("packetDeltaCount", flows.FlowFeature, func() flows.Feature { return &packetDeltaCountPacket{} }, flows.RawPacket)
	flows.RegisterStandardFeature("octetDeltaCount", flows.FlowFeature, func() flows.Feature { return &octetDeltaCountPacket{} }, flows.RawPacket)

	// flows.RegisterCustomFunction("ingressInterface", "", resolveConst, flows.FlowFeature, func() flows.Feature { return &interfaceFeature{} }, flows.FlowFeature)
	// flows.RegisterStandardFeature("interfaceName", flows.FlowFeature, func() flows.Feature { return &interfaceNameFeature{} }, flows.Const)
	// flows.RegisterCustomFunction("interfaceName", "", resolveConst, flows.FlowFeature, func() flows.Feature { return &interfaceNameFeature{} }, flows.FlowFeature)
}
