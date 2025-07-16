# Floor

Floor is a fully decentralised gaming smart contract that enables provably fair games using any ERC20 token or ETH. The contract relies on resolvers—independent addresses that hold liquidity and sign game actions—to determine the outcome of each game. There is no contract owner and anyone can act as a resolver.

## Features

- **Multi-asset support**: games may be played with ETH or any ERC20 token.
- **Provable fairness**: games store a hash of the initial seed, configuration and algorithm. When the resolver publishes the final seed, players can verify the outcome off chain.
- **Permit2 integration**: optional gasless approvals for ERC20 tokens.
- **Open resolver system**: deposits and withdrawals are permissionless.

## Getting started

This repository uses [Foundry](https://book.getfoundry.sh) for development. After cloning the repo, install dependencies and run the tests:

```bash
forge test -vvv
```

### Building

```bash
forge build
```

### Formatting

```bash
forge fmt
```

## Basic usage

1. **Provide liquidity**
   - Call `depositETH()` to deposit Ether or `deposit(token, amount)` to deposit ERC20 tokens. Deposits are credited to the caller as a resolver.
2. **Create a game**
   - Players call `createGame` (or `createGameWithPermit2` for Permit2) with parameters signed by a resolver. ETH bets are sent as `msg.value`. ERC20 bets are transferred from the player.
3. **Resolve the game**
   - The resolver determines the outcome and calls `cashOut` or `markGameAsLost` with a signature if necessary. The contract transfers winnings to the player and accounts for the resolver’s balance.
4. **Withdraw liquidity**
   - Resolvers may call `withdrawETH` or `withdraw` at any time to retrieve unused funds.

## Contracts

The primary contract is [`src/Floor.sol`](src/Floor.sol). Unit tests are located in [`test/Floor.t.sol`](test/Floor.t.sol).

## Deployment

A minimal deployment script is provided in [`script/Abstract.Deploy.sol`](script/Abstract.Deploy.sol). Custom scripts can inherit from it to deploy `Floor` with the desired Permit2 address.

