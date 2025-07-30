// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";

/**
 * @title CommitReveal
 * @dev A fully decentralized gaming contract that supports any asset (ETH/ERC20) with provable fairness
 *
 * Features:
 * - Multi-asset support (ETH and any ERC20 token)
 * - Provable fairness through cryptographic commitments
 * - IPFS algorithm storage for immutable verification
 * - Open resolver system (anyone can be a resolver with their own liquidity)
 * - Fully decentralized (no owner or admin)
 * - Permit2 integration for gasless ERC20 approvals
 */
contract CommitReveal is
    Initializable,
    ReentrancyGuardUpgradeable,
    EIP712Upgradeable,
    UUPSUpgradeable,
    Ownable2StepUpgradeable
{
    using SafeERC20 for IERC20;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Address representing ETH (0x0)
    address public constant ETH_ADDRESS = address(0);

    /// @notice Permit2 contract address
    ISignatureTransfer public immutable PERMIT2;

    /// @notice EIP-712 type hashes
    bytes32 public constant CREATE_GAME_TYPEHASH = keccak256(
        "CreateGame(address token,uint256 betAmount,bytes32 gameSeedHash,bytes32 algorithm,bytes32 gameConfig,address player,uint256 deadline)"
    );

    bytes32 public constant CASH_OUT_TYPEHASH =
        keccak256("CashOut(bytes32 gameId,uint256 payoutAmount,bytes32 gameState,bytes32 gameSeed,uint256 deadline)");

    bytes32 public constant MARK_GAME_AS_LOST_TYPEHASH =
        keccak256("MarkGameAsLost(bytes32 gameId,bytes32 gameState,bytes32 gameSeed,uint256 deadline)");

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           STRUCTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Struct to group game creation parameters
    struct CreateGameParams {
        address token;
        uint256 betAmount;
        bytes32 gameSeedHash;
        bytes32 algorithm;
        bytes32 gameConfig;
        uint256 deadline;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      STATE VARIABLES                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Mapping to track used signature hashes to prevent replay attacks
    mapping(bytes32 signatureHash => bool used) public usedSignatures;

    /// @notice Mapping of resolver balances by token
    mapping(address resolver => mapping(address token => uint256 balance)) public balanceOf;

    /// @notice Reserved slots for upgradeability
    uint256[50] private __gap; // 50 reserved slots

    /// @notice Game status enum
    enum GameStatus {
        None, // Default state (0) - game doesn't exist
        Active, // Game is active and can be played
        Won, // Game was won by player
        Lost // Game was lost by player

    }

    /// @notice Game data structure
    struct Game {
        GameStatus status; // Current game status
        address player; // Player's wallet address
        address resolver; // Resolver who will handle this game
        address token; // ETH_ADDRESS (0x0) for ETH, token address for ERC20
        uint256 betAmount; // Amount bet in wei/token units
        uint256 payoutAmount; // Final payout amount (0 if lost)
        bytes32 gameSeedHash; // Hash of the seed + gameConfig + algorithm
        bytes32 gameSeed; // Seed used to generate the game state
        bytes32 algorithm; // IPFS CID (as bytes32) pointing to the deterministic algorithm
        bytes32 gameConfig; // CID of game configuration JSON
        bytes32 gameState; // CID of final game state/player moves JSON
        bytes32 salt; // User-provided entropy to prevent seed premining
    }

    /// @notice Mapping from game signature hash to Game data
    mapping(bytes32 signatureHash => Game game) internal _games;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Emitted when a new game is created
    event GameCreated(
        bytes32 gameId,
        address player,
        address resolver,
        address token,
        uint256 betAmount,
        bytes32 gameSeedHash,
        bytes32 salt
    );

    /// @notice Emitted when a payout is sent to a player
    event PayoutSent(
        bytes32 gameId,
        address resolver,
        address token,
        uint256 amount,
        address recipient,
        bytes32 gameState,
        bytes32 gameSeed
    );

    /// @notice Emitted when a game is lost
    event GameLost(bytes32 gameId, address resolver, bytes32 gameState, bytes32 gameSeed);

    /// @notice Emitted when a resolver deposits funds
    event Deposit(address resolver, address token, uint256 amount);

    /// @notice Emitted when a resolver withdraws funds
    event Withdraw(address resolver, address token, uint256 amount);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           ERRORS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    error SignatureAlreadyUsed(bytes32 signatureHash);
    error GameDoesNotExist(bytes32 gameId);
    error GameNotActive(bytes32 gameId);
    error InvalidResolverSignature();
    error InsufficientContractBalance(address token, uint256 required, uint256 available);
    error InvalidAmount(uint256 amount);
    error InvalidAsset();
    error InvalidPermitTransfer();
    error SignatureExpired();
    error InvalidSignature();
    error TokenMismatch();
    error InsufficientPermitAmount();
    error ETHTransferFailed();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CONSTRUCTOR                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(address _permit2) {
        PERMIT2 = ISignatureTransfer(_permit2);
        _disableInitializers();
    }

    function initialize(address _owner) public initializer {
        __Ownable_init(_owner);
        __ReentrancyGuard_init();
        __EIP712_init("CommitReveal", "1");
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     EXTERNAL FUNCTIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Get game data by game ID
     * @param gameId The game ID (signature hash)
     * @return game The Game struct containing all game data
     */
    function games(bytes32 gameId) external view returns (Game memory game) {
        return _games[gameId];
    }

    /**
     * @notice Creates a new game. Supports both ETH and ERC20 tokens.
     * @param params Game creation parameters grouped in a struct
     * @param serverSignature Signature from the server authorizing this game creation
     * @param salt User-provided entropy to prevent seed premining (not part of server signature)
     */
    function createGame(CreateGameParams calldata params, bytes calldata serverSignature, bytes32 salt)
        external
        payable
        nonReentrant
    {
        if (block.timestamp > params.deadline) revert SignatureExpired();
        if (params.betAmount == 0) revert InvalidAmount(params.betAmount);

        // Calculate game ID from signature hash
        bytes32 gameId = keccak256(serverSignature);

        if (usedSignatures[gameId]) {
            revert SignatureAlreadyUsed(gameId);
        }

        // Verify resolver signature
        address resolver = _verifyCreateGameSignature(params, msg.sender, serverSignature);

        // Handle asset transfer
        if (params.token == ETH_ADDRESS) {
            if (msg.value != params.betAmount) revert InvalidAmount(params.betAmount);
        } else {
            if (msg.value != 0) revert InvalidAmount(msg.value);
            IERC20(params.token).safeTransferFrom(msg.sender, address(this), params.betAmount);
        }

        _createGame(params, resolver, msg.sender, gameId, salt);
    }

    /**
     * @notice Creates a new game using Permit2 for gasless ERC20 approvals
     * @param params Game creation parameters grouped in a struct
     * @param serverSignature Signature from the server authorizing this game creation
     * @param salt User-provided entropy to prevent seed premining (not part of server signature)
     * @param permit Permit2 permit data signed by the player
     * @param transferDetails Details of the token transfer (to, requestedAmount)
     * @param permitSignature Player's signature for the Permit2 transfer
     */
    function createGameWithPermit2(
        CreateGameParams calldata params,
        bytes calldata serverSignature,
        bytes32 salt,
        ISignatureTransfer.PermitTransferFrom memory permit,
        ISignatureTransfer.SignatureTransferDetails calldata transferDetails,
        bytes calldata permitSignature
    ) external nonReentrant {
        if (block.timestamp > params.deadline) revert SignatureExpired();
        if (params.betAmount == 0) revert InvalidAmount(params.betAmount);

        // Calculate game ID from signature hash
        bytes32 gameId = keccak256(serverSignature);

        if (usedSignatures[gameId]) {
            revert SignatureAlreadyUsed(gameId);
        }

        // Verify resolver signature
        address resolver = _verifyCreateGameSignature(params, msg.sender, serverSignature);

        // Verify permit token matches params
        if (permit.permitted.token != params.token) revert TokenMismatch();

        // Verify permit amount is sufficient
        if (permit.permitted.amount < params.betAmount) revert InsufficientPermitAmount();

        // Verify transfer details are safe
        if (transferDetails.to != address(this)) revert InvalidPermitTransfer();
        if (transferDetails.requestedAmount != params.betAmount) revert InvalidAmount(transferDetails.requestedAmount);

        // Transfer tokens using Permit2
        PERMIT2.permitTransferFrom(permit, transferDetails, msg.sender, permitSignature);

        _createGame(params, resolver, msg.sender, gameId, salt);
    }

    /**
     * @notice Processes a cash out for a winning game
     * @param gameId The game ID (signature hash from game creation)
     * @param payoutAmount The amount to pay out
     * @param gameState CID of final game state/player moves JSON
     * @param gameSeed The final game seed to store for provable fairness
     * @param deadline The latest timestamp this signature is valid for (only required if called by player)
     * @param serverSignature Signature from an admin (only required if called by player)
     */
    function cashOut(
        bytes32 gameId,
        uint256 payoutAmount,
        bytes32 gameState,
        bytes32 gameSeed,
        uint256 deadline,
        bytes calldata serverSignature
    ) external nonReentrant {
        Game storage game = _games[gameId];
        if (game.status == GameStatus.None) {
            revert GameDoesNotExist(gameId);
        }
        if (game.status != GameStatus.Active) {
            revert GameNotActive(gameId);
        }
        if (payoutAmount == 0) revert InvalidAmount(payoutAmount);

        // Verify authorization - resolver can resolve directly, others need resolver signature
        if (msg.sender != game.resolver) {
            if (block.timestamp > deadline) revert SignatureExpired();
            bytes32 messageHash = _hashTypedDataV4(
                keccak256(abi.encode(CASH_OUT_TYPEHASH, gameId, payoutAmount, gameState, gameSeed, deadline))
            );
            if (_verifyAndGetResolver(messageHash, serverSignature) != game.resolver) revert InvalidResolverSignature();
        }

        // Check resolver has sufficient balance
        if (balanceOf[game.resolver][game.token] < payoutAmount) {
            revert InsufficientContractBalance(game.token, payoutAmount, balanceOf[game.resolver][game.token]);
        }

        // Update game state
        game.status = GameStatus.Won;
        game.payoutAmount = payoutAmount;
        game.gameState = gameState;
        game.gameSeed = gameSeed;

        // Update balances - deduct payout from resolver (bet amount already added at game creation)
        unchecked {
            balanceOf[game.resolver][game.token] -= payoutAmount;
        }

        // Transfer payout to player
        if (game.token == ETH_ADDRESS) {
            (bool success,) = payable(game.player).call{value: payoutAmount}("");
            if (!success) {
                revert ETHTransferFailed();
            }
        } else {
            IERC20(game.token).safeTransfer(game.player, payoutAmount);
        }

        emit PayoutSent(gameId, game.resolver, game.token, payoutAmount, game.player, gameState, gameSeed);
    }

    /**
     * @notice Mark a game as lost
     * @param gameId The game ID (signature hash from game creation)
     * @param gameState CID of final game state/player moves JSON
     * @param gameSeed The final game seed to store for provable fairness
     * @param deadline The latest timestamp this signature is valid for (only required if called by player)
     * @param serverSignature Signature from an admin (only required if called by player)
     */
    function markGameAsLost(
        bytes32 gameId,
        bytes32 gameState,
        bytes32 gameSeed,
        uint256 deadline,
        bytes calldata serverSignature
    ) external {
        Game storage game = _games[gameId];
        if (game.status == GameStatus.None) {
            revert GameDoesNotExist(gameId);
        }
        if (game.status != GameStatus.Active) {
            revert GameNotActive(gameId);
        }

        // Verify authorization - resolver can resolve directly, others need resolver signature
        if (msg.sender != game.resolver) {
            if (block.timestamp > deadline) revert SignatureExpired();
            bytes32 messageHash = _hashTypedDataV4(
                keccak256(abi.encode(MARK_GAME_AS_LOST_TYPEHASH, gameId, gameState, gameSeed, deadline))
            );
            if (_verifyAndGetResolver(messageHash, serverSignature) != game.resolver) revert InvalidResolverSignature();
        }

        // Update game state
        game.status = GameStatus.Lost;
        game.gameState = gameState;
        game.gameSeed = gameSeed;

        // No balance update needed - bet amount already added to resolver at game creation

        emit GameLost(gameId, game.resolver, gameState, gameSeed);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    RESOLVER MANAGEMENT                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Deposit ETH as a resolver to provide liquidity for games
     */
    function depositETH() external payable nonReentrant {
        if (msg.value == 0) revert InvalidAmount(msg.value);
        unchecked {
            balanceOf[msg.sender][ETH_ADDRESS] += msg.value;
        }
        emit Deposit(msg.sender, ETH_ADDRESS, msg.value);
    }

    /**
     * @notice Deposit ERC20 tokens as a resolver to provide liquidity for games
     * @param token Token address
     * @param amount Amount to deposit
     */
    function deposit(address token, uint256 amount) external nonReentrant {
        if (token == ETH_ADDRESS) revert InvalidAsset();
        if (amount == 0) revert InvalidAmount(amount);
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        balanceOf[msg.sender][token] += amount;
        emit Deposit(msg.sender, token, amount);
    }

    /**
     * @notice Deposit ERC20 tokens using Permit2 for gasless approvals
     * @param permit Permit2 permit data signed by the depositor
     * @param permitSignature Depositor's signature for the Permit2 transfer
     */
    function depositWithPermit2(ISignatureTransfer.PermitTransferFrom memory permit, bytes calldata permitSignature)
        external
        nonReentrant
    {
        address token = permit.permitted.token;
        uint256 amount = permit.permitted.amount;

        if (token == ETH_ADDRESS) revert InvalidAsset();
        if (amount == 0) revert InvalidAmount(amount);

        // Create transfer details - use full permitted amount
        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            ISignatureTransfer.SignatureTransferDetails({to: address(this), requestedAmount: amount});

        // Transfer tokens using Permit2
        PERMIT2.permitTransferFrom(permit, transferDetails, msg.sender, permitSignature);

        // Update balance
        balanceOf[msg.sender][token] += amount;
        emit Deposit(msg.sender, token, amount);
    }

    /**
     * @notice Withdraw ETH from resolver balance
     * @param amount The amount to withdraw
     */
    function withdrawETH(uint256 amount) external nonReentrant {
        if (amount == 0) revert InvalidAmount(amount);
        if (amount > balanceOf[msg.sender][ETH_ADDRESS]) {
            revert InsufficientContractBalance(ETH_ADDRESS, amount, balanceOf[msg.sender][ETH_ADDRESS]);
        }

        unchecked {
            balanceOf[msg.sender][ETH_ADDRESS] -= amount;
        }

        (bool success,) = payable(msg.sender).call{value: amount}("");
        if (!success) revert ETHTransferFailed();

        emit Withdraw(msg.sender, ETH_ADDRESS, amount);
    }

    /**
     * @notice Withdraw ERC20 tokens from resolver balance
     * @param token Token address
     * @param amount The amount to withdraw
     */
    function withdraw(address token, uint256 amount) external nonReentrant {
        if (token == ETH_ADDRESS) revert InvalidAsset();
        if (amount == 0) revert InvalidAmount(amount);
        if (amount > balanceOf[msg.sender][token]) {
            revert InsufficientContractBalance(token, amount, balanceOf[msg.sender][token]);
        }

        unchecked {
            balanceOf[msg.sender][token] -= amount;
        }
        IERC20(token).safeTransfer(msg.sender, amount);

        emit Withdraw(msg.sender, token, amount);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     INTERNAL FUNCTION                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @dev Verifies signature and returns the resolver address
     * @param _hash The hash that was signed
     * @param _signature The signature bytes
     * @return resolver The address of the resolver who signed
     */
    function _verifyAndGetResolver(bytes32 _hash, bytes calldata _signature) internal pure returns (address) {
        address recoveredSigner = ECDSA.recover(_hash, _signature);
        if (recoveredSigner == address(0)) {
            revert InvalidResolverSignature();
        }
        return recoveredSigner;
    }

    /**
     * @dev Verifies the signature of a game creation request and returns the resolver address.
     * @param params Game creation parameters struct
     * @param player The address of the player creating the game.
     * @param serverSignature Signature from the server authorizing this game creation.
     * @return resolver The address of the resolver who signed.
     */
    function _verifyCreateGameSignature(
        CreateGameParams calldata params,
        address player,
        bytes calldata serverSignature
    ) internal view returns (address) {
        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    CREATE_GAME_TYPEHASH,
                    params.token,
                    params.betAmount,
                    params.gameSeedHash,
                    params.algorithm,
                    params.gameConfig,
                    player,
                    params.deadline
                )
            )
        );
        return _verifyAndGetResolver(messageHash, serverSignature);
    }

    /**
     * @dev Creates a new game and emits the GameCreated event.
     * @param params Game creation parameters struct
     * @param resolver The address of the resolver who created the game.
     * @param player The address of the player creating the game.
     * @param gameId The unique game ID derived from signature hash.
     * @param salt User-provided entropy to prevent seed premining.
     */
    function _createGame(
        CreateGameParams calldata params,
        address resolver,
        address player,
        bytes32 gameId,
        bytes32 salt
    ) internal {
        // Mark signature hash as used
        usedSignatures[gameId] = true;

        // Add bet amount to resolver's balance (house edge)
        balanceOf[resolver][params.token] += params.betAmount;

        // Create game using signature hash as ID
        _games[gameId] = Game({
            status: GameStatus.Active,
            player: player,
            resolver: resolver,
            token: params.token,
            betAmount: params.betAmount,
            gameSeedHash: params.gameSeedHash,
            payoutAmount: 0,
            gameSeed: bytes32(0),
            algorithm: params.algorithm,
            gameConfig: params.gameConfig,
            gameState: bytes32(0),
            salt: salt // Store the salt
        });
        emit GameCreated(gameId, player, resolver, params.token, params.betAmount, params.gameSeedHash, salt);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    UPGRADE AUTHORIZATION                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
