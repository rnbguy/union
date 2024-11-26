package types

import (
	"cosmossdk.io/core/registry"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/msgservice"
	// authzcodec "cosmossdk.io/x/authz/codec"
)

var (
	amino = codec.NewLegacyAmino()

	// ModuleCdc references the global erc20 module codec. Note, the codec should
	// ONLY be used in certain instances of tests and for JSON encoding.
	//
	// The actual codec used for serialization should be provided to modules/erc20 and
	// defined at the application level.
	ModuleCdc = codec.NewProtoCodec(codectypes.NewInterfaceRegistry())

	// AminoCdc is a amino codec created to support amino JSON compatible msgs.
	AminoCdc = codec.NewLegacyAmino()
)

const (
	// Amino names
	createTFDenom      = "tokenfactory/create-denom"
	mintTFDenom        = "tokenfactory/mint"
	burnTFDenom        = "tokenfactory/burn"
	changeAdminTFDenom = "tokenfactory/change-admin"
)

// NOTE: This is required for the GetSignBytes function
func init() {
	RegisterLegacyAminoCodec(amino)

	sdk.RegisterLegacyAminoCodec(amino)
	// cryptocodec.RegisterCrypto(amino)
	// codec.RegisterEvidences(amino)

	// Register all Amino interfaces and concrete types on the authz Amino codec
	// so that this can later be used to properly serialize MsgGrant and MsgExec
	// instances.
	legacyAmino := codec.NewLegacyAmino()
	RegisterLegacyAminoCodec(legacyAmino)

	amino.Seal()
}

func RegisterInterfaces(registry registry.InterfaceRegistrar) {
	registry.RegisterImplementations(
		(*sdk.Msg)(nil),
		&MsgCreateDenom{},
		&MsgMint{},
		&MsgBurn{},
		&MsgChangeAdmin{},
	)
	msgservice.RegisterMsgServiceDesc(registry, &_Msg_serviceDesc)
}

func RegisterLegacyAminoCodec(registrar registry.AminoRegistrar) {
	registrar.RegisterConcrete(&MsgCreateDenom{}, createTFDenom)
	registrar.RegisterConcrete(&MsgMint{}, mintTFDenom)
	registrar.RegisterConcrete(&MsgBurn{}, burnTFDenom)
	registrar.RegisterConcrete(&MsgChangeAdmin{}, changeAdminTFDenom)
}
