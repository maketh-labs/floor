# Floor

This repository contains two smart contracts for building decentralized gambling platforms:

- **CommitReveal**: A verifiable on-chain gaming contract that eliminates the need for VRF
- **SignedVault**: A deposit/withdrawal system for backend-controlled games with trusted resolvers

## Contracts Overview

### CommitReveal (`src/CommitReveal.sol`)

**CommitReveal** enables verifiable on-chain games by tracking all necessary components to prove the backend didn't cheat. This eliminates the need for VRF (Verifiable Random Function) by storing the game algorithm, settings, user-provided salt, and seed hash on-chain.

**Key Features:**
- **Verifiable fairness**: Tracks game algorithm (IPFS CID), settings, user salt, and seed hash
- **No VRF needed**: Complete game verification through on-chain data
- **Multi-asset support**: Games can be played with ETH or any ERC20 token
- **User-provided entropy**: Players add salt after server commitment to prevent premining
- **Open resolver system**: Anyone can be a resolver with their own liquidity
- **Permit2 integration**: Gasless ERC20 approvals for better UX

### SignedVault (`src/SignedVault.sol`)

**SignedVault** is designed for games that are primarily controlled by the backend. Users deposit funds, but withdrawals require signatures from trusted resolvers who determine the proper payout amounts.

**Key Features:**
- **Backend-controlled games**: Trusted resolvers determine payouts via signatures
- **Secure deposits**: Anyone can deposit ETH or ERC20 tokens for any resolver
- **Signature-required withdrawals**: Resolvers must sign to authorize specific payouts
- **Deposit verification**: Backend can verify deposits using deterministic hashes
- **Multi-asset support**: Supports ETH and any ERC20 token
- **Signature cancellation**: Ability to invalidate signatures before use
- **Permit2 integration**: Gasless ERC20 approvals

## Getting Started

This repository uses [Foundry](https://book.getfoundry.sh) for development. After cloning the repo, install dependencies and run the tests:

```shell
forge test
```

### Building

```shell
forge build
```

### Formatting

```shell
forge fmt
```

## Usage Guide

### CommitReveal Contract Usage (Verifiable On-Chain Games)

#### 1. **Resolver Setup**
   - Deposit liquidity: Call `depositETH()` for Ether or `deposit(token, amount)` for ERC20 tokens
   - Deposits are credited to the caller as a resolver balance

#### 2. **Game Creation** 
   - Server creates game parameters and signs them (without user salt)
   - Player receives signed parameters and adds their own salt (entropy)
   - Player calls `createGame()` with parameters, server signature, and their salt
   - For ETH games: Send bet amount as `msg.value`
   - For ERC20 games: Use `createGameWithPermit2()` for gasless approvals
   - All verification data (algorithm, config, salt, seed hash) is stored on-chain

#### 3. **Game Resolution & Verification**
   - Resolver determines outcome and calls either:
     - `cashOut()`: For winning games, pays out to player with final game state and seed
     - `markGameAsLost()`: For losing games, stores final game state and seed
   - Players can verify fairness by checking:
     - Algorithm (IPFS CID) matches expected game logic
     - Game config matches what was agreed upon
     - Their salt was used (prevents server premining)
     - Final seed produces the claimed outcome when run through the algorithm

#### 4. **Liquidity Management**
   - Resolvers can call `withdrawETH()` or `withdraw()` to retrieve unused funds

### SignedVault Contract Usage (Backend-Controlled Games)

#### 1. **Deposit Funds**
   - Anyone can deposit for any resolver with a unique nonce:
     - `depositETH(resolver, nonce)`: Deposit ETH for a specific resolver
     - `deposit(resolver, token, amount, nonce)`: Deposit ERC20 tokens
     - `depositWithPermit2()`: Deposit ERC20 with gasless approval
   - Backend can verify deposits using the deterministic hash system

#### 2. **Game Resolution**
   - Backend determines game outcomes off-chain
   - Trusted resolver signs withdrawal authorization for proper payout amount
   - Players call withdrawal functions with resolver signature

#### 3. **Withdraw Funds**
   - Withdrawals require resolver signatures:
     - `withdrawETH()`: Withdraw ETH with resolver signature
     - `withdraw()`: Withdraw ERC20 tokens with resolver signature
   - Signatures include deadline for time-based security
   - Signatures can be cancelled if needed using `cancelSignature()`

## File Structure

```
src/
├── CommitReveal.sol      # Main gaming contract
└── SignedVault.sol       # Deposit/withdrawal contract

test/
├── CommitReveal.t.sol    # CommitReveal tests
└── SignedVault.t.sol     # SignedVault tests

script/
├── DeployCommitReveal.s.sol    # CommitReveal deployment
└── DeploySignedVault.s.sol     # SignedVault deployment
```

## Deployment

Deployment scripts are provided for both contracts:

- [`script/DeployCommitReveal.s.sol`](script/DeployCommitReveal.s.sol) - Deploy CommitReveal contract
- [`script/DeploySignedVault.s.sol`](script/DeploySignedVault.s.sol) - Deploy SignedVault contract

Both contracts use UUPS proxy pattern for upgradeability and require a Permit2 address for deployment.

