package app

import (
	"encoding/json"
	"log"

	"cosmossdk.io/collections"
	storetypes "cosmossdk.io/store/types"
	slashingtypes "cosmossdk.io/x/slashing/types"
	"cosmossdk.io/x/staking"
	stakingtypes "cosmossdk.io/x/staking/types"

	cmtproto "github.com/cometbft/cometbft/api/cometbft/types/v1"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// ExportAppStateAndValidators exports the state of the application for a genesis
// file.
func (app *UnionApp) ExportAppStateAndValidators(
	forZeroHeight bool,
	jailAllowedAddrs []string,
	modulesToExport []string,
) (servertypes.ExportedApp, error) {
	// as if they could withdraw from the start of the next block
	ctx := app.NewContextLegacy(true, cmtproto.Header{Height: app.LastBlockHeight()})

	// We export at last height + 1, because that's the height at which
	// Tendermint will start InitChain.
	height := app.LastBlockHeight() + 1
	if forZeroHeight {
		height = 0
		app.prepForZeroHeightGenesis(ctx, jailAllowedAddrs)
	}

	genState, err := app.ModuleManager.ExportGenesisForModules(ctx, modulesToExport)
	if err != nil {
		return servertypes.ExportedApp{}, err
	}

	appState, err := json.MarshalIndent(genState, "", "  ")
	if err != nil {
		return servertypes.ExportedApp{}, err
	}

	validators, err := staking.WriteValidators(ctx, app.StakingKeeper)
	if err != nil {
		return servertypes.ExportedApp{}, err
	}
	return servertypes.ExportedApp{
		AppState:        appState,
		Validators:      validators,
		Height:          height,
		ConsensusParams: app.BaseApp.GetConsensusParams(ctx),
	}, nil
}

// prepare for fresh start at zero height
// NOTE zero height genesis is a temporary feature which will be deprecated
// in favour of export at a block height
func (app *UnionApp) prepForZeroHeightGenesis(ctx sdk.Context, jailAllowedAddrs []string) {
	applyAllowedAddrs := false

	// check if there is a allowed address list
	if len(jailAllowedAddrs) > 0 {
		applyAllowedAddrs = true
	}

	allowedAddrsMap := make(map[string]bool)

	for _, addr := range jailAllowedAddrs {
		_, err := sdk.ValAddressFromBech32(addr)
		if err != nil {
			log.Fatal(err)
		}
		allowedAddrsMap[addr] = true
	}

	/* Handle fee distribution state. */

	// withdraw all validator commission
	app.StakingKeeper.IterateValidators(ctx, func(_ int64, val sdk.ValidatorI) (stop bool) {
		valbz, err := app.StakingKeeper.ValidatorAddressCodec().StringToBytes(val.GetOperator())
		if err != nil {
			panic(err)
		}

		_, err = app.DistrKeeper.WithdrawValidatorCommission(ctx, valbz)
		if err != nil {
			panic(err)
		}
		return false
	})

	// withdraw all delegator rewards
	dels, err := app.StakingKeeper.GetAllDelegations(ctx)
	if err != nil {
		panic(err)
	}

	for _, delegation := range dels {
		valAddr, err := sdk.ValAddressFromBech32(delegation.ValidatorAddress)
		if err != nil {
			panic(err)
		}

		delAddr := sdk.MustAccAddressFromBech32(delegation.DelegatorAddress)

		_, err = app.DistrKeeper.WithdrawDelegationRewards(ctx, delAddr, valAddr)
		if err != nil {
			panic(err)
		}
	}

	// clear validator slash events
	err = app.DistrKeeper.ValidatorSlashEvents.Clear(ctx, nil)
	if err != nil {
		panic(err)
	}

	// clear validator historical rewards
	err = app.DistrKeeper.ValidatorHistoricalRewards.Clear(ctx, nil)
	if err != nil {
		panic(err)
	}

	// set context height to zero
	height := ctx.BlockHeight()
	ctx = ctx.WithBlockHeight(0)

	// reinitialize all validators
	app.StakingKeeper.IterateValidators(ctx, func(_ int64, val sdk.ValidatorI) (stop bool) {
		// donate any unwithdrawn outstanding reward fraction tokens to the community pool
		valbz, err := app.StakingKeeper.ValidatorAddressCodec().StringToBytes(val.GetOperator())
		if err != nil {
			panic(err)
		}
		// donate any unwithdrawn outstanding reward fraction tokens to the community pool
		scraps, err := app.DistrKeeper.GetValidatorOutstandingRewardsCoins(ctx, valbz)
		if err != nil {
			panic(err)
		}

		feePool, err := app.DistrKeeper.FeePool.Get(ctx)
		if err != nil {
			panic(err)
		}
		feePool.CommunityPool = feePool.CommunityPool.Add(scraps...)
		app.DistrKeeper.FeePool.Set(ctx, feePool)

		err = app.DistrKeeper.Hooks().AfterValidatorCreated(ctx, valbz)
		if err != nil {
			panic(err)
		}
		return false
	})

	// reinitialize all delegations
	for _, del := range dels {
		valAddr, err := sdk.ValAddressFromBech32(del.ValidatorAddress)
		if err != nil {
			panic(err)
		}
		delAddr := sdk.MustAccAddressFromBech32(del.DelegatorAddress)

		err = app.DistrKeeper.Hooks().BeforeDelegationCreated(ctx, delAddr, valAddr)
		if err != nil {
			panic(err)
		}
		err = app.DistrKeeper.Hooks().AfterDelegationModified(ctx, delAddr, valAddr)
		if err != nil {
			panic(err)
		}
	}

	// reset context height
	ctx = ctx.WithBlockHeight(height)

	/* Handle staking state. */

	// iterate through redelegations, reset creation height
	app.StakingKeeper.IterateRedelegations(ctx, func(_ int64, red stakingtypes.Redelegation) (stop bool) {
		for i := range red.Entries {
			red.Entries[i].CreationHeight = 0
		}
		app.StakingKeeper.SetRedelegation(ctx, red)
		return false
	})

	// iterate through unbonding delegations, reset creation height
	err = app.StakingKeeper.UnbondingDelegations.Walk(
		ctx,
		nil,
		func(_ collections.Pair[[]byte, []byte], ubd stakingtypes.UnbondingDelegation) (stop bool, err error) {
			for i := range ubd.Entries {
				ubd.Entries[i].CreationHeight = 0
			}
			err = app.StakingKeeper.SetUnbondingDelegation(ctx, ubd)
			if err != nil {
				return true, err
			}
			return false, err
		},
	)
	if err != nil {
		panic(err)
	}

	// Iterate through validators by power descending, reset bond heights, and
	// update bond intra-tx counters.
	store := ctx.KVStore(app.keys[stakingtypes.StoreKey])
	iter := storetypes.KVStoreReversePrefixIterator(store, stakingtypes.ValidatorsKey)
	counter := int16(0)

	for ; iter.Valid(); iter.Next() {
		addr := sdk.ValAddress(iter.Key()[1:])
		validator, err := app.StakingKeeper.GetValidator(ctx, addr)
		if err != nil {
			panic("expected validator, not found")
		}

		validator.UnbondingHeight = 0
		if applyAllowedAddrs && !allowedAddrsMap[addr.String()] {
			validator.Jailed = true
		}

		app.StakingKeeper.SetValidator(ctx, validator)
		counter++
	}

	iter.Close()

	if _, err := app.StakingKeeper.ApplyAndReturnValidatorSetUpdates(ctx); err != nil {
		panic(err)
	}

	/* Handle slashing state. */

	// reset start height on signing infos
	err = app.SlashingKeeper.ValidatorSigningInfo.Walk(ctx, nil, func(addr sdk.ConsAddress, info slashingtypes.ValidatorSigningInfo) (stop bool, err error) {
		info.StartHeight = 0
		err = app.SlashingKeeper.ValidatorSigningInfo.Set(ctx, addr, info)
		if err != nil {
			return true, err
		}
		return false, nil
	})
	if err != nil {
		panic(err)
	}
}
