package ibc

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"

	"cosmossdk.io/core/store"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	capabilitytypes "github.com/cosmos/ibc-go/modules/capability/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	connectiontypes "github.com/cosmos/ibc-go/v8/modules/core/03-connection/types"
	channeltypes "github.com/cosmos/ibc-go/v8/modules/core/04-channel/types"
	porttypes "github.com/cosmos/ibc-go/v8/modules/core/05-port/types"
	host "github.com/cosmos/ibc-go/v8/modules/core/24-host"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	ibckeeper "github.com/cosmos/ibc-go/v8/modules/core/keeper"
	stack "github.com/emirpasic/gods/stacks/linkedliststack"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"golang.org/x/crypto/sha3"
)

const (
	StoreKey = "ethibc"

	EthConnectionCommitmentPrefix = 0x02
	EthChannelCommitmentPrefix    = 0x03
	EthPacketsCommitmentPrefix    = 0x04
	EthPacketAcksCommitmentPrefix = 0x05
	EthNextSeqSendPrefix          = 0x06
	EthNextSeqRecvPrefix          = 0x07
	EthNextSeqAckPrefix           = 0x08
)

var (
	_ porttypes.Middleware = &DoubleCommitMiddleware{}
	_ store.KVStoreService = &DoubleCommitStore{}

	CommitmentMagic = [32]byte{01}

	EthUint32, _     = abi.NewType("uint32", "", nil)
	EthUint8, _      = abi.NewType("uint8", "", nil)
	EthBytes32, _    = abi.NewType("bytes32", "", nil)
	EthConnection, _ = abi.NewType("tuple", "struct ethConnection", []abi.ArgumentMarshaling{
		{Name: "state", Type: "uint8"},
		{Name: "clientId", Type: "uint32"},
		{Name: "counterpartyClientId", Type: "uint32"},
		{Name: "counterpartyConnectionId", Type: "uint32"},
	})
	EthChannel, _ = abi.NewType("tuple", "struct ethChannel", []abi.ArgumentMarshaling{
		{Name: "state", Type: "uint8"},
		{Name: "ordering", Type: "uint8"},
		{Name: "connectionId", Type: "uint32"},
		{Name: "counterpartyChannelId", Type: "uint32"},
		{Name: "counterpartyPortId", Type: "string"},
		{Name: "version", Type: "string"},
	})
	EthPacket, _ = abi.NewType("tuple", "struct ethPacket", []abi.ArgumentMarshaling{
		{Name: "sequence", Type: "uint64"},
		{Name: "sourceChannel", Type: "uint32"},
		{Name: "destinationChannel", Type: "uint32"},
		{Name: "data", Type: "uint32"},
		{Name: "timeoutHeight", Type: "uint64"},
		{Name: "timeoutTimestamp", Type: "uint64"},
	})
)

type ethConnection struct {
	State                    uint8
	ClientId                 uint32
	CounterpartyClientId     uint32
	CounterpartyConnectionId uint32
}

type ethChannel struct {
	State                 uint8
	Ordering              uint8
	ConnectionId          uint32
	CounterpartyChannelId uint32
	CounterpartyPortId    string
	Version               string
}

type ethPacket struct {
	Sequence           uint64
	SourceChannel      uint32
	DestinationChannel uint32
	Data               []byte
	TimeoutHeight      uint64
	TimeoutTimestamp   uint64
}

type DoubleCommitMiddleware struct {
	ibc         *ibckeeper.Keeper
	app         porttypes.IBCModule
	ics4Wrapper porttypes.ICS4Wrapper
	store       *DoubleCommitStore
}

type CommitMiddleware interface {
	porttypes.IBCModule
}

func NewDoubleCommitMiddleware(
	ibc *ibckeeper.Keeper,
	app porttypes.IBCModule,
	ics4Wrapper porttypes.ICS4Wrapper,
	store *DoubleCommitStore,
) CommitMiddleware {
	return &DoubleCommitMiddleware{
		ibc:         ibc,
		app:         app,
		ics4Wrapper: ics4Wrapper,
		store:       store,
	}
}

// OnChanOpenInit implements the IBCModule interface.
func (im DoubleCommitMiddleware) OnChanOpenInit(
	ctx context.Context,
	order channeltypes.Order,
	connectionHops []string,
	portID string,
	channelID string,
	chanCap *capabilitytypes.Capability,
	counterparty channeltypes.Counterparty,
	version string,
) (string, error) {
	return im.app.OnChanOpenInit(ctx, order, connectionHops, portID, channelID, chanCap, counterparty, version)
}

// OnChanOpenTry implements the IBCModule interface.
func (im DoubleCommitMiddleware) OnChanOpenTry(
	ctx context.Context,
	order channeltypes.Order,
	connectionHops []string,
	portID, channelID string,
	chanCap *capabilitytypes.Capability,
	counterparty channeltypes.Counterparty,
	counterpartyVersion string,
) (version string, err error) {
	return im.app.OnChanOpenTry(ctx, order, connectionHops, portID, channelID, chanCap, counterparty, counterpartyVersion)
}

// OnChanOpenAck implements the IBCModule interface.
func (im DoubleCommitMiddleware) OnChanOpenAck(
	ctx context.Context,
	portID, channelID string,
	counterpartyChannelID string,
	counterpartyVersion string,
) error {
	return im.app.OnChanOpenAck(ctx, portID, channelID, counterpartyChannelID, counterpartyVersion)
}

func (im DoubleCommitMiddleware) OnChanOpenConfirm(ctx context.Context, portID, channelID string) error {
	return im.app.OnChanOpenConfirm(ctx, portID, channelID)
}

func (im DoubleCommitMiddleware) OnChanCloseInit(ctx context.Context, portID, channelID string) error {
	return im.app.OnChanCloseInit(ctx, portID, channelID)
}

func (im DoubleCommitMiddleware) OnChanCloseConfirm(ctx context.Context, portID, channelID string) error {
	return im.app.OnChanCloseConfirm(ctx, portID, channelID)
}

func (im DoubleCommitMiddleware) OnRecvPacket(
	ctx context.Context,
	packet channeltypes.Packet,
	relayer sdk.AccAddress,
) ibcexported.Acknowledgement {
	im.store.processingPackets.Push(packet)
	defer im.store.processingPackets.Pop()
	return im.app.OnRecvPacket(ctx, packet, relayer)
}

func (im DoubleCommitMiddleware) OnAcknowledgementPacket(
	ctx context.Context,
	packet channeltypes.Packet,
	acknowledgement []byte,
	relayer sdk.AccAddress,
) error {
	im.store.processingPackets.Push(packet)
	defer im.store.processingPackets.Pop()
	return im.app.OnAcknowledgementPacket(ctx, packet, acknowledgement, relayer)
}

func (im DoubleCommitMiddleware) OnTimeoutPacket(
	ctx context.Context,
	packet channeltypes.Packet,
	relayer sdk.AccAddress,
) error {
	im.store.processingPackets.Push(packet)
	defer im.store.processingPackets.Pop()
	return im.app.OnTimeoutPacket(ctx, packet, relayer)
}

func (im DoubleCommitMiddleware) SendPacket(
	ctx context.Context,
	chanCap *capabilitytypes.Capability,
	sourcePort string,
	sourceChannel string,
	timeoutHeight clienttypes.Height,
	timeoutTimestamp uint64,
	data []byte,
) (sequence uint64, err error) {
	channel, found := im.ibc.ChannelKeeper.GetChannel(ctx, sourcePort, sourceChannel)
	if found {
		im.store.processingPackets.Push(
			channeltypes.Packet{
				Sequence:           0, // parsed from the callback
				SourcePort:         sourcePort,
				SourceChannel:      sourceChannel,
				DestinationPort:    channel.Counterparty.PortId,
				DestinationChannel: channel.Counterparty.ChannelId,
				TimeoutHeight:      timeoutHeight,
				TimeoutTimestamp:   timeoutTimestamp,
				Data:               data,
			},
		)
		defer im.store.processingPackets.Pop()
	}
	return im.ics4Wrapper.SendPacket(ctx, chanCap, sourcePort, sourceChannel, timeoutHeight, timeoutTimestamp, data)
}

func (im DoubleCommitMiddleware) WriteAcknowledgement(
	ctx context.Context,
	chanCap *capabilitytypes.Capability,
	packet ibcexported.PacketI,
	ack ibcexported.Acknowledgement,
) error {
	im.store.processingPackets.Push(packet)
	defer im.store.processingPackets.Pop()
	im.store.processingAcks.Push(ack)
	defer im.store.processingAcks.Pop()
	return im.ics4Wrapper.WriteAcknowledgement(ctx, chanCap, packet, ack)
}

func (im DoubleCommitMiddleware) GetAppVersion(
	ctx context.Context,
	portID,
	channelID string,
) (string, bool) {
	return im.ics4Wrapper.GetAppVersion(ctx, portID, channelID)
}

type DoubleCommitStore struct {
	cdc               codec.Codec
	commitKey         *storetypes.KVStoreKey
	ibcKey            *storetypes.KVStoreKey
	processingPackets *stack.Stack
	processingAcks    *stack.Stack
}

func NewDoubleCommitStoreService(
	cdc codec.Codec,
	commitKey *storetypes.KVStoreKey,
	ibcKey *storetypes.KVStoreKey,
) *DoubleCommitStore {
	return &DoubleCommitStore{
		cdc:               cdc,
		commitKey:         commitKey,
		ibcKey:            ibcKey,
		processingPackets: stack.New(),
		processingAcks:    stack.New(),
	}
}

func (t *DoubleCommitStore) OpenKVStore(ctx context.Context) store.KVStore {
	return newKVStore(
		t.cdc,
		sdk.UnwrapSDKContext(ctx).KVStore(t.commitKey),
		sdk.UnwrapSDKContext(ctx).KVStore(t.ibcKey),
		t.processingPackets,
		t.processingAcks,
	)
}

type coreDoubleCommitStore struct {
	cdc               codec.Codec
	commitStore       storetypes.KVStore
	ibcStore          storetypes.KVStore
	processingPackets *stack.Stack
	processingAcks    *stack.Stack
}

func newKVStore(cdc codec.Codec, commitStore storetypes.KVStore, ibcStore storetypes.KVStore, processingPackets *stack.Stack, processingAcks *stack.Stack) store.KVStore {
	return coreDoubleCommitStore{
		cdc:               cdc,
		commitStore:       commitStore,
		ibcStore:          ibcStore,
		processingPackets: processingPackets,
		processingAcks:    processingAcks,
	}
}

func (s coreDoubleCommitStore) Get(key []byte) ([]byte, error) {
	return s.ibcStore.Get(key), nil
}

func (s coreDoubleCommitStore) Has(key []byte) (bool, error) {
	return s.ibcStore.Has(key), nil
}

func (s coreDoubleCommitStore) Set(key, value []byte) error {
	// base commit
	s.ibcStore.Set(key, value)
	// double commit depending on the path, ordered by hotest to coldest path
	keyStr := string(key)
	// packet commitment
	if strings.HasPrefix(keyStr, host.KeyPacketCommitmentPrefix) {
		if sequence, channelId, err := parsePacketCommitmentPath(keyStr); err == nil {
			packet, found := s.processingPackets.Peek()
			if !found {
				return fmt.Errorf("the impossible happened")
			}
			batchHash, err := commitPacket(sequence, packet.(ibcexported.PacketI))
			if err != nil {
				return nil
			}
			commitmentKey, err := batchPacketsCommitmentKey(channelId, batchHash)
			if err != nil {
				return nil
			}
			s.commitStore.Set(commitmentKey, CommitmentMagic[:])
		}
		return nil
	}
	if strings.HasPrefix(keyStr, host.KeyPacketReceiptPrefix) {
		if sequence, channelId, err := parsePacketReceiptPath(keyStr); err == nil {
			packet, found := s.processingPackets.Peek()
			if !found {
				return fmt.Errorf("the impossible happened")
			}
			batchHash, err := commitPacket(sequence, packet.(ibcexported.PacketI))
			if err != nil {
				return nil
			}
			commitmentKey, err := batchPacketsReceiptCommitmentKey(channelId, batchHash)
			if err != nil {
				return nil
			}
			s.commitStore.Set(commitmentKey, CommitmentMagic[:])
		}
		return nil
	}
	if strings.HasPrefix(keyStr, host.KeyPacketAckPrefix) {
		if sequence, channelId, err := parsePacketAckPath(keyStr); err == nil {
			packet, found := s.processingPackets.Peek()
			if !found {
				return fmt.Errorf("the impossible happened")
			}
			ackI, ackFound := s.processingAcks.Peek()
			if !ackFound {
				return fmt.Errorf("the impossible happened")
			}
			batchHash, err := commitPacket(sequence, packet.(ibcexported.PacketI))
			if err != nil {
				return nil
			}
			commitmentKey, err := batchPacketsReceiptCommitmentKey(channelId, batchHash)
			if err != nil {
				return nil
			}
			// The MSB should be a bool indicating the receipt, the 31 bytes left are the acknowledgement hash
			ack := keccak(ackI.(ibcexported.Acknowledgement).Acknowledgement())
			ack[0] = 01
			s.commitStore.Set(commitmentKey, ack[:])
		}
		return nil
	}
	if strings.HasPrefix(keyStr, host.KeyNextSeqSendPrefix) {
		if channelId, err := parseNextSequence(host.KeyNextSeqSendPrefix, keyStr); err == nil {
			commitmentKey, err := nextSequenceCommitmentKey(EthNextSeqSendPrefix, channelId)
			if err != nil {
				return err
			}
			s.commitStore.Set(commitmentKey, value)
		}
		return nil
	}
	if strings.HasPrefix(keyStr, host.KeyNextSeqRecvPrefix) {
		if channelId, err := parseNextSequence(host.KeyNextSeqRecvPrefix, keyStr); err == nil {
			commitmentKey, err := nextSequenceCommitmentKey(EthNextSeqRecvPrefix, channelId)
			if err != nil {
				return err
			}
			s.commitStore.Set(commitmentKey, value)
		}
		return nil
	}
	if strings.HasPrefix(keyStr, host.KeyNextSeqAckPrefix) {
		if channelId, err := parseNextSequence(host.KeyNextSeqAckPrefix, keyStr); err == nil {
			commitmentKey, err := nextSequenceCommitmentKey(EthNextSeqAckPrefix, channelId)
			if err != nil {
				return err
			}
			s.commitStore.Set(commitmentKey, value)
		}
		return nil
	}
	// channel commitment
	if strings.HasPrefix(keyStr, host.KeyChannelEndPrefix) {
		_, channelId, err := host.ParseChannelPath(keyStr)
		if err != nil {
			return nil
		}
		id, err := channeltypes.ParseChannelSequence(channelId)
		if err != nil {
			return nil
		}
		if id > math.MaxUint32 {
			return fmt.Errorf(
				"can't parse channel, id > MaxUint32: %d",
				id,
			)
		}
		var channel channeltypes.Channel
		s.cdc.MustUnmarshal(value, &channel)
		commitmentValue, err := commitChannel(channel)
		if err != nil {
			return err
		}
		commitmentKey, err := channelCommitmentKey(uint32(id))
		if err != nil {
			return err
		}
		s.commitStore.Set(commitmentKey, commitmentValue)
		return nil
	}
	// connection commitment
	if strings.HasPrefix(keyStr, host.KeyConnectionPrefix) {
		connectionId, err := host.ParseConnectionPath(keyStr)
		if err != nil {
			return nil
		}
		id, err := connectiontypes.ParseConnectionSequence(connectionId)
		if err != nil {
			return nil
		}
		if id > math.MaxUint32 {
			return fmt.Errorf(
				"can't parse connection, id > MaxUint32: %d",
				id,
			)
		}
		var connection connectiontypes.ConnectionEnd
		s.cdc.MustUnmarshal(value, &connection)
		commitmentValue, err := commitConnection(connection)
		if err != nil {
			return err
		}
		commitmentKey, err := connectionCommitmentKey(uint32(id))
		if err != nil {
			return err
		}
		s.commitStore.Set(commitmentKey, commitmentValue)
		return nil
	}
	return nil
}

func (s coreDoubleCommitStore) Delete(key []byte) error {
	s.ibcStore.Delete(key)
	return nil
}

func (s coreDoubleCommitStore) Iterator(start, end []byte) (store.Iterator, error) {
	return s.ibcStore.Iterator(start, end), nil
}

func (s coreDoubleCommitStore) ReverseIterator(start, end []byte) (store.Iterator, error) {
	return s.ibcStore.ReverseIterator(start, end), nil
}

func parseNextSequence(typ string, path string) (uint32, error) {
	split := strings.Split(path, "/")
	if len(split) < 5 {
		return 0, fmt.Errorf("cannot parse next sequence path, invalid fragments")
	}
	if split[0] != typ ||
		split[1] != host.KeyPortPrefix ||
		split[3] != host.KeyChannelPrefix {
		return 0, fmt.Errorf("cannot parse next sequence path, invalid prefixes")
	}
	channel := split[4]
	channelId, err := channeltypes.ParseChannelSequence(channel)
	if err != nil {
		return 0, err
	}
	if channelId > math.MaxUint32 {
		return 0, fmt.Errorf(
			"can't parse packet commitment, channel id > MaxUint32: %d",
			channelId,
		)
	}
	return uint32(channelId), nil
}

// "commitments/ports/{identifier}/channels/{identifier}/sequences/{sequence}"
func parsePacketCommitmentPath(path string) (uint64, uint32, error) {
	split := strings.Split(path, "/")
	if len(split) < 7 {
		return 0, 0, fmt.Errorf("cannot parse packet commitment path, invalid fragments")
	}
	if split[0] != host.KeyPacketCommitmentPrefix ||
		split[1] != host.KeyPortPrefix ||
		split[3] != host.KeyChannelPrefix ||
		split[5] != host.KeySequencePrefix {
		return 0, 0, fmt.Errorf("cannot parse packet commitment path, invalid prefixes")
	}
	sequence, err := strconv.ParseUint(split[6], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("cannot parse packet commitment path, invalid sequence")
	}
	channel := split[4]
	channelId, err := channeltypes.ParseChannelSequence(channel)
	if err != nil {
		return 0, 0, err
	}
	if channelId > math.MaxUint32 {
		return 0, 0, fmt.Errorf(
			"can't parse packet commitment, channel id > MaxUint32: %d",
			channelId,
		)
	}
	return sequence, uint32(channelId), nil
}

// "acks/ports/{identifier}/channels/{identifier}/sequences/{sequence}"
func parsePacketAckPath(path string) (uint64, uint32, error) {
	split := strings.Split(path, "/")
	if len(split) < 7 {
		return 0, 0, fmt.Errorf("cannot parse packet ack path, invalid fragments")
	}
	if split[0] != host.KeyPacketAckPrefix ||
		split[1] != host.KeyPortPrefix ||
		split[3] != host.KeyChannelPrefix ||
		split[5] != host.KeySequencePrefix {
		return 0, 0, fmt.Errorf("cannot parse packet ack path, invalid prefixes")
	}
	sequence, err := strconv.ParseUint(split[6], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("cannot parse packet ack path, invalid sequence")
	}
	channel := split[4]
	channelId, err := channeltypes.ParseChannelSequence(channel)
	if err != nil {
		return 0, 0, err
	}
	if channelId > math.MaxUint32 {
		return 0, 0, fmt.Errorf(
			"can't parse packet commitment, channel id > MaxUint32: %d",
			channelId,
		)
	}
	return sequence, uint32(channelId), nil
}

// "receipts/ports/{identifier}/channels/{identifier}/sequences/{sequence}"
func parsePacketReceiptPath(path string) (uint64, uint32, error) {
	split := strings.Split(path, "/")
	if len(split) < 7 {
		return 0, 0, fmt.Errorf("cannot parse packet receipt path, invalid fragments")
	}
	if split[0] != host.KeyPacketReceiptPrefix ||
		split[1] != host.KeyPortPrefix ||
		split[3] != host.KeyChannelPrefix ||
		split[5] != host.KeySequencePrefix {
		return 0, 0, fmt.Errorf("cannot parse packet receipt path, invalid prefixes")
	}
	sequence, err := strconv.ParseUint(split[6], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("cannot parse packet receipt path, invalid sequence")
	}
	channel := split[4]
	channelId, err := channeltypes.ParseChannelSequence(channel)
	if err != nil {
		return 0, 0, err
	}
	if channelId > math.MaxUint32 {
		return 0, 0, fmt.Errorf(
			"can't parse packet commitment, channel id > MaxUint32: %d",
			channelId,
		)
	}
	return sequence, uint32(channelId), nil
}

func keccak(bz []byte) [32]byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(bz)
	var buf [32]byte
	copy(buf[:], hash.Sum(nil))
	return buf
}

func commitChannel(channel channeltypes.Channel) ([]byte, error) {
	if len(channel.ConnectionHops) != 1 {
		return nil, fmt.Errorf(
			"can't commit channel, expected 1 connection hop, got %d",
			len(channel.ConnectionHops),
		)
	}
	connectionId, err := connectiontypes.ParseConnectionSequence(channel.ConnectionHops[0])
	if err != nil {
		return nil, err
	}
	if connectionId > math.MaxUint32 {
		return nil, fmt.Errorf(
			"can't commit channel, connectionId > MaxUint32: %d",
			connectionId,
		)
	}
	counterpartyChannelId, err := channeltypes.ParseChannelSequence(channel.Counterparty.ChannelId)
	if err != nil {
		// Default to zero
		counterpartyChannelId = 0
	}
	if counterpartyChannelId > math.MaxUint32 {
		return nil, fmt.Errorf(
			"can't commit channel, counterpartyChannelId > MaxUint32: %d",
			counterpartyChannelId,
		)
	}
	arguments := abi.Arguments{
		{Name: "channel", Type: EthChannel},
	}
	bytes, err := arguments.Pack(
		&ethChannel{
			State:                 uint8(channel.State),
			Ordering:              uint8(channel.Ordering),
			ConnectionId:          uint32(connectionId),
			CounterpartyChannelId: uint32(counterpartyChannelId),
			CounterpartyPortId:    channel.Counterparty.PortId,
			Version:               channel.Version,
		},
	)
	if err != nil {
		return nil, err
	}
	hash := keccak(bytes)
	return hash[:], nil
}

func commitConnection(connection connectiontypes.ConnectionEnd) ([]byte, error) {
	_, clientId, err := clienttypes.ParseClientIdentifier(connection.ClientId)
	if err != nil {
		return nil, err
	}
	if clientId > math.MaxUint32 {
		return nil, fmt.Errorf(
			"can't commit connection, clientId > MaxUint32: %d",
			clientId,
		)
	}
	_, counterpartyClientId, err := clienttypes.ParseClientIdentifier(connection.Counterparty.ClientId)
	if err != nil {
		return nil, err
	}
	if counterpartyClientId > math.MaxUint32 {
		return nil, fmt.Errorf(
			"can't commit connection, counterpartyClientId > MaxUint32: %d",
			counterpartyClientId,
		)
	}
	counterpartyConnectionId, err := connectiontypes.ParseConnectionSequence(connection.Counterparty.ConnectionId)
	if err != nil {
		// Default to zero
		counterpartyConnectionId = 0
	}
	if counterpartyConnectionId > math.MaxUint32 {
		return nil, fmt.Errorf(
			"can't commit connection, counterpartyConnectionId > MaxUint32: %d",
			counterpartyConnectionId,
		)
	}
	arguments := abi.Arguments{
		{Name: "connection", Type: EthConnection},
	}
	bytes, err := arguments.Pack(
		&ethConnection{
			State:                    uint8(connection.State),
			ClientId:                 uint32(clientId),
			CounterpartyClientId:     uint32(counterpartyClientId),
			CounterpartyConnectionId: uint32(counterpartyConnectionId),
		},
	)
	if err != nil {
		return nil, err
	}
	hash := keccak(bytes)
	return hash[:], nil
}

func commitPacket(sequence uint64, packet ibcexported.PacketI) ([32]byte, error) {
	sourceChannel, err := channeltypes.ParseChannelSequence(packet.GetSourceChannel())
	if err != nil {
		return [32]byte{}, err
	}
	if sourceChannel > math.MaxUint32 {
		return [32]byte{}, fmt.Errorf(
			"can't parse channel, sourceChannel > MaxUint32: %d",
			sourceChannel,
		)
	}
	destinationChannel, err := channeltypes.ParseChannelSequence(packet.GetDestChannel())
	if err != nil {
		return [32]byte{}, err
	}
	if destinationChannel > math.MaxUint32 {
		return [32]byte{}, fmt.Errorf(
			"can't parse channel, destinationChannel > MaxUint32: %d",
			destinationChannel,
		)
	}
	arguments := abi.Arguments{
		{Name: "packet", Type: EthPacket},
	}
	bytes, err := arguments.Pack(
		&ethPacket{
			Sequence:           sequence,
			SourceChannel:      uint32(sourceChannel),
			DestinationChannel: uint32(destinationChannel),
			Data:               packet.GetData(),
			TimeoutHeight:      packet.GetTimeoutHeight().GetRevisionHeight(),
			TimeoutTimestamp:   packet.GetTimeoutTimestamp(),
		},
	)
	if err != nil {
		return [32]byte{}, err
	}
	return keccak(bytes), nil
}

func connectionCommitmentKey(connectionId uint32) ([]byte, error) {
	arguments := abi.Arguments{
		{Name: "prefix", Type: EthUint8},
		{Name: "connectionId", Type: EthUint32},
	}
	bytes, err := arguments.Pack(
		uint8(EthConnectionCommitmentPrefix),
		connectionId,
	)
	if err != nil {
		return nil, err
	}
	hash := keccak(bytes)
	return hash[:], nil
}

func channelCommitmentKey(channelId uint32) ([]byte, error) {
	arguments := abi.Arguments{
		{Name: "prefix", Type: EthUint8},
		{Name: "channelId", Type: EthUint32},
	}
	bytes, err := arguments.Pack(
		uint8(EthChannelCommitmentPrefix),
		channelId,
	)
	if err != nil {
		return nil, err
	}
	hash := keccak(bytes)
	return hash[:], nil
}

func batchPacketsCommitmentKey(channelId uint32, batchHash [32]byte) ([]byte, error) {
	arguments := abi.Arguments{
		{Name: "prefix", Type: EthUint8},
		{Name: "channelId", Type: EthUint32},
		{Name: "batchHash", Type: EthBytes32},
	}
	bytes, err := arguments.Pack(
		uint8(EthPacketsCommitmentPrefix),
		channelId,
		batchHash,
	)
	if err != nil {
		return nil, err
	}
	hash := keccak(bytes)
	return hash[:], nil
}

func batchPacketsReceiptCommitmentKey(channelId uint32, batchHash [32]byte) ([]byte, error) {
	arguments := abi.Arguments{
		{Name: "prefix", Type: EthUint8},
		{Name: "channelId", Type: EthUint32},
		{Name: "batchHash", Type: EthBytes32},
	}
	bytes, err := arguments.Pack(
		uint8(EthPacketAcksCommitmentPrefix),
		channelId,
		batchHash,
	)
	if err != nil {
		return nil, err
	}
	hash := keccak(bytes)
	return hash[:], nil
}

func nextSequenceCommitmentKey(prefix int, channelId uint32) ([]byte, error) {
	arguments := abi.Arguments{
		{Name: "prefix", Type: EthUint8},
		{Name: "channelId", Type: EthUint32},
	}
	bytes, err := arguments.Pack(
		uint8(prefix),
		channelId,
	)
	if err != nil {
		return nil, err
	}
	hash := keccak(bytes)
	return hash[:], nil
}
