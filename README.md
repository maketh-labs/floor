# CommitReveal & SignedVault

This repository contains two complementary smart contracts for building decentralized gaming platforms:

- **CommitReveal**: A provably fair gaming contract with commit-reveal scheme
- **SignedVault**: A secure deposit/withdrawal system with signature-based authorization

## Contracts Overview

### CommitReveal (`src/CommitReveal.sol`)

**CommitReveal** enables provably fair games using any ERC20 token or ETH. The contract uses a commit-reveal scheme where game outcomes are determined by cryptographic commitments that are later revealed, ensuring fairness and preventing manipulation.

**Key Features:**
- **Multi-asset support**: Games can be played with ETH or any ERC20 token
- **Provable fairness**: Uses commit-reveal cryptography with IPFS algorithm storage
- **Open resolver system**: Anyone can be a resolver with their own liquidity
- **Permit2 integration**: Gasless ERC20 approvals for better UX
- **Signature-based game IDs**: Uses keccak hash of server signatures to prevent front-running

### SignedVault (`src/SignedVault.sol`)

**SignedVault** is a deposit/withdrawal contract where users can deposit funds for specific resolvers, but withdrawals require resolver signatures. This provides a secure way to manage resolver liquidity.

**Key Features:**
- **Free deposits**: Anyone can deposit ETH or ERC20 tokens for any resolver
- **Controlled withdrawals**: Require resolver signatures to prevent unauthorized access
- **Resolver balance tracking**: Track balances by resolver to prevent over-withdrawals
- **Multi-asset support**: Supports ETH and any ERC20 token
- **Signature replay protection**: Uses signature hashes to prevent replay attacks
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

### CommitReveal Contract Usage

#### 1. **Resolver Setup**
   - Deposit liquidity: Call `depositETH()` for Ether or `deposit(token, amount)` for ERC20 tokens
   - Deposits are credited to the caller as a resolver balance

#### 2. **Game Creation** 
   - Players call `createGame()` with parameters signed by a resolver
   - For ETH games: Send bet amount as `msg.value`
   - For ERC20 games: Approve tokens first, or use `createGameWithPermit2()` for gasless approvals
   - Game ID is derived from the keccak hash of the server signature (prevents front-running)

#### 3. **Game Resolution**
   - Resolver determines outcome and calls either:
     - `cashOut()`: For winning games, pays out to player
     - `markGameAsLost()`: For losing games, keeps bet amount
   - Both functions store the final game state and seed for verification

#### 4. **Liquidity Management**
   - Resolvers can call `withdrawETH()` or `withdraw()` to retrieve unused funds
   - Bet amounts are automatically added to resolver balance at game creation

### SignedVault Contract Usage

#### 1. **Deposit Funds**
   - Anyone can deposit for any resolver:
     - `depositETH(resolver)`: Deposit ETH for a specific resolver
     - `deposit(resolver, token, amount)`: Deposit ERC20 tokens
     - `depositWithPermit2()`: Deposit ERC20 with gasless approval

#### 2. **Check Balances**
   - Use `getResolverBalance(resolver, token)` to check resolver's balance for a specific token
   - Balances are tracked per resolver per token

#### 3. **Withdraw Funds**
   - Only resolvers can withdraw their own funds using signed authorizations:
     - `withdrawETH()`: Withdraw ETH with resolver signature
     - `withdraw()`: Withdraw ERC20 tokens with resolver signature
   - Signatures include deadline and nonce for security

## Contract Architecture

```
┌─────────────────┐    ┌─────────────────┐
│   CommitReveal  │    │   SignedVault   │
│                 │    │                 │
│ • Game Logic    │    │ • Deposit Funds │
│ • Bet Handling  │    │ • Secure Withdrawals │
│ • Commit-Reveal │    │ • Balance Tracking │
│ • Provable Fair │    │ • Signature Auth │
└─────────────────┘    └─────────────────┘
        │                        │
        └────── Can be used ──────┘
            independently or
              together
```

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

