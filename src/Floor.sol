// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";

/**
 * @title Floor
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
contract Floor is Initializable, ReentrancyGuardUpgradeable, EIP712Upgradeable, UUPSUpgradeable, OwnableUpgradeable {
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
        "CreateGame(uint256 nonce,address token,uint256 betAmount,bytes32 gameSeedHash,bytes32 algorithm,bytes32 gameConfig,address player,uint256 deadline)"
    );

    bytes32 public constant CASH_OUT_TYPEHASH =
        keccak256("CashOut(uint256 id,uint256 payoutAmount,bytes32 gameState,string gameSeed,uint256 deadline)");

    bytes32 public constant MARK_GAME_AS_LOST_TYPEHASH =
        keccak256("MarkGameAsLost(uint256 id,bytes32 gameState,string gameSeed,uint256 deadline)");

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           STRUCTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Struct to group game creation parameters
    struct CreateGameParams {
        uint256 nonce;
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

    /// @notice Counter for generating unique game IDs
    uint256 public count;

    /// @notice Mapping to track used nonces to prevent signature replay attacks
    mapping(uint256 nonce => bool used) public usedNonces;

    /// @notice Mapping of resolver balances by token
    mapping(address resolver => mapping(address token => uint256 balance)) public balanceOf;

    /// @notice Game status enum
    enum GameStatus {
        Active,
        Won,
        Lost
    }

    /// @notice Game data structure
    struct Game {
        uint256 createdAt; // Block timestamp when game was created
        address player; // Player's wallet address
        address resolver; // Resolver who will handle this game
        GameStatus status; // Current game status
        address token; // ETH_ADDRESS (0x0) for ETH, token address for ERC20
        uint256 betAmount; // Amount bet in wei/token units
        uint256 payoutAmount; // Final payout amount (0 if lost)
        bytes32 gameSeedHash; // Hash of the seed + gameConfig + algorithm
        string gameSeed; // Seed used to generate the game state
        bytes32 algorithm; // IPFS CID (as bytes32) pointing to the deterministic algorithm
        bytes32 gameConfig; // CID of game configuration JSON
        bytes32 gameState; // CID of final game state/player moves JSON
    }

    /// @notice Mapping from on-chain game ID to Game data
    mapping(uint256 id => Game game) public games;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Emitted when a new game is created
    event GameCreated(
        uint256 nonce,
        uint256 indexed id,
        address indexed player,
        address indexed resolver,
        address token,
        uint256 betAmount,
        bytes32 gameSeedHash
    );

    /// @notice Emitted when a payout is sent to a player
    event PayoutSent(
        uint256 indexed id, address indexed resolver, address indexed token, uint256 amount, address recipient
    );

    /// @notice Emitted when a game is lost
    event GameLost(uint256 indexed id, address indexed resolver);

    /// @notice Emitted when a resolver deposits funds
    event Deposit(address indexed resolver, address indexed token, uint256 amount);

    /// @notice Emitted when a resolver withdraws funds
    event Withdraw(address indexed resolver, address indexed token, uint256 amount);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           ERRORS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    error NonceAlreadyUsed(uint256 nonce);
    error GameDoesNotExist(uint256 id);
    error GameNotActive(uint256 id);
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
        __EIP712_init("Floor", "1");
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     EXTERNAL FUNCTIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Creates a new game. Supports both ETH and ERC20 tokens.
     * @param params Game creation parameters grouped in a struct
     * @param serverSignature Signature from the server authorizing this game creation
     */
    function createGame(CreateGameParams calldata params, bytes calldata serverSignature)
        external
        payable
        nonReentrant
    {
        if (block.timestamp > params.deadline) revert SignatureExpired();
        if (params.betAmount == 0) revert InvalidAmount(params.betAmount);

        if (usedNonces[params.nonce]) {
            revert NonceAlreadyUsed(params.nonce);
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

        _createGame(params, resolver, msg.sender);
    }

    /**
     * @notice Creates a new game using Permit2 for gasless ERC20 approvals
     * @param params Game creation parameters grouped in a struct
     * @param serverSignature Signature from the server authorizing this game creation
     * @param permit Permit2 permit data signed by the player
     * @param transferDetails Details of the token transfer (to, requestedAmount)
     * @param permitSignature Player's signature for the Permit2 transfer
     */
    function createGameWithPermit2(
        CreateGameParams calldata params,
        bytes calldata serverSignature,
        ISignatureTransfer.PermitTransferFrom memory permit,
        ISignatureTransfer.SignatureTransferDetails calldata transferDetails,
        bytes calldata permitSignature
    ) external nonReentrant {
        if (block.timestamp > params.deadline) revert SignatureExpired();
        if (params.betAmount == 0) revert InvalidAmount(params.betAmount);

        if (usedNonces[params.nonce]) {
            revert NonceAlreadyUsed(params.nonce);
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

        _createGame(params, resolver, msg.sender);
    }

    /**
     * @notice Processes a cash out for a winning game
     * @param id The game ID
     * @param payoutAmount The amount to pay out
     * @param gameState CID of final game state/player moves JSON
     * @param gameSeed The final game seed to store for provable fairness
     * @param deadline The latest timestamp this signature is valid for (only required if called by player)
     * @param serverSignature Signature from an admin (only required if called by player)
     */
    function cashOut(
        uint256 id,
        uint256 payoutAmount,
        bytes32 gameState,
        string calldata gameSeed,
        uint256 deadline,
        bytes calldata serverSignature
    ) external nonReentrant {
        Game storage game = games[id];
        if (game.player == address(0)) {
            revert GameDoesNotExist(id);
        }
        if (game.status != GameStatus.Active) {
            revert GameNotActive(id);
        }
        if (payoutAmount == 0) revert InvalidAmount(payoutAmount);

        // Verify authorization - resolver can resolve directly, others need resolver signature
        if (msg.sender != game.resolver) {
            if (block.timestamp > deadline) revert SignatureExpired();
            bytes32 messageHash = _hashTypedDataV4(
                keccak256(
                    abi.encode(CASH_OUT_TYPEHASH, id, payoutAmount, gameState, keccak256(bytes(gameSeed)), deadline)
                )
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

        // Update balances - deduct from resolver, add bet amount to resolver (house edge)
        balanceOf[game.resolver][game.token] -= payoutAmount;
        balanceOf[game.resolver][game.token] += game.betAmount;

        // Transfer payout to player
        if (game.token == ETH_ADDRESS) {
            (bool success,) = payable(game.player).call{value: payoutAmount}("");
            if (!success) {
                revert ETHTransferFailed();
            }
        } else {
            IERC20(game.token).safeTransfer(game.player, payoutAmount);
        }

        emit PayoutSent(id, game.resolver, game.token, payoutAmount, game.player);
    }

    /**
     * @notice Mark a game as lost
     * @param id The game ID
     * @param gameState CID of final game state/player moves JSON
     * @param gameSeed The final game seed to store for provable fairness
     * @param deadline The latest timestamp this signature is valid for (only required if called by player)
     * @param serverSignature Signature from an admin (only required if called by player)
     */
    function markGameAsLost(
        uint256 id,
        bytes32 gameState,
        string calldata gameSeed,
        uint256 deadline,
        bytes calldata serverSignature
    ) external {
        Game storage game = games[id];
        if (game.player == address(0)) {
            revert GameDoesNotExist(id);
        }
        if (game.status != GameStatus.Active) {
            revert GameNotActive(id);
        }

        // Verify authorization - resolver can resolve directly, others need resolver signature
        if (msg.sender != game.resolver) {
            if (block.timestamp > deadline) revert SignatureExpired();
            bytes32 messageHash = _hashTypedDataV4(
                keccak256(abi.encode(MARK_GAME_AS_LOST_TYPEHASH, id, gameState, keccak256(bytes(gameSeed)), deadline))
            );
            if (_verifyAndGetResolver(messageHash, serverSignature) != game.resolver) revert InvalidResolverSignature();
        }

        // Update game state
        game.status = GameStatus.Lost;
        game.gameState = gameState;
        game.gameSeed = gameSeed;

        // Add bet amount to resolver's balance (house keeps the bet)
        balanceOf[game.resolver][game.token] += game.betAmount;

        emit GameLost(id, game.resolver);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    RESOLVER MANAGEMENT                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Deposit ETH as a resolver to provide liquidity for games
     */
    function depositETH() external payable {
        if (msg.value == 0) revert InvalidAmount(msg.value);
        balanceOf[msg.sender][ETH_ADDRESS] += msg.value;
        emit Deposit(msg.sender, ETH_ADDRESS, msg.value);
    }

    /**
     * @notice Deposit ERC20 tokens as a resolver to provide liquidity for games
     * @param token Token address
     * @param amount Amount to deposit
     */
    function deposit(address token, uint256 amount) external {
        if (token == ETH_ADDRESS) revert InvalidAsset();
        if (amount == 0) revert InvalidAmount(amount);
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
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

        balanceOf[msg.sender][ETH_ADDRESS] -= amount;

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

        balanceOf[msg.sender][token] -= amount;
        IERC20(token).safeTransfer(msg.sender, amount);

        emit Withdraw(msg.sender, token, amount);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      RECEIVE FUNCTION                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Receive function to accept direct ETH deposits (credited to sender as resolver)
     */
    receive() external payable {
        balanceOf[msg.sender][ETH_ADDRESS] += msg.value;
        emit Deposit(msg.sender, ETH_ADDRESS, msg.value);
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
                    params.nonce,
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
     */
    function _createGame(CreateGameParams calldata params, address resolver, address player) internal {
        // Mark nonce as used
        usedNonces[params.nonce] = true;

        // Create game
        count += 1;

        games[count] = Game({
            player: player,
            resolver: resolver,
            token: params.token,
            betAmount: params.betAmount,
            gameSeedHash: params.gameSeedHash,
            status: GameStatus.Active,
            payoutAmount: 0,
            gameSeed: "",
            algorithm: params.algorithm,
            gameConfig: params.gameConfig,
            gameState: "",
            createdAt: block.timestamp
        });
        emit GameCreated(params.nonce, count, player, resolver, params.token, params.betAmount, params.gameSeedHash);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    UPGRADE AUTHORIZATION                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        STORAGE GAP                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // @notice Reserved slots for upgradeability
    uint256[50] private __gap; // 50 reserved slots
}
