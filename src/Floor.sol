// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

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
 * - Prepared for Permit2 integration
 */
contract Floor is ReentrancyGuard, EIP712 {
    using SafeERC20 for IERC20;

    // ♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣
    //                      CONSTANTS
    // ♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣

    /// @notice Address representing ETH (0x0)
    address public constant ETH_ADDRESS = address(0);

    /// @notice EIP-712 type hashes
    bytes32 public constant CREATE_GAME_TYPEHASH = keccak256(
        "CreateGame(uint256 nonce,address token,uint256 betAmount,bytes32 gameSeedHash,bytes32 algorithm,bytes32 gameConfig,address player,uint256 deadline)"
    );

    bytes32 public constant CASH_OUT_TYPEHASH =
        keccak256("CashOut(uint256 id,uint256 payoutAmount,bytes32 gameState,string gameSeed,uint256 deadline)");

    bytes32 public constant MARK_GAME_AS_LOST_TYPEHASH =
        keccak256("MarkGameAsLost(uint256 id,bytes32 gameState,string gameSeed,uint256 deadline)");

    // ♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣
    //                   STATE VARIABLES
    // ♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣

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

    // ♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣
    //                        EVENTS
    // ♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣

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

    // ♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣
    //                        ERRORS
    // ♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣

    error NonceAlreadyUsed(uint256 nonce);
    error GameDoesNotExist(uint256 id);
    error GameNotActive(uint256 id);
    error PayoutFailed(uint256 id, address token, uint256 amount);
    error InvalidResolverSignature();
    error UnsupportedAsset(address token);
    error InsufficientContractBalance(address token, uint256 required, uint256 available);
    error InvalidAmount(uint256 amount);
    error InvalidAsset();

    // ♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣
    //                     CONSTRUCTOR
    // ♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣

    /**
     * @dev Constructor sets initial configuration
     */
    constructor() EIP712("Floor", "1") {
        // EIP712 handles domain separation automatically
    }

    // ♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣
    //                  EXTERNAL FUNCTIONS
    // ♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣

    /**
     * @notice Creates a new game. Supports both ETH and ERC20 tokens.
     * @param nonce Unique nonce to prevent signature replay attacks
     * @param token Token address (ETH_ADDRESS for ETH, token address for ERC20)
     * @param betAmount Amount to bet (in wei for ETH, token units for ERC20)
     * @param gameSeedHash Hash of the game seed for provable fairness
     * @param algorithm IPFS CID (as bytes32) pointing to the deterministic algorithm
     * @param gameConfig CID of game configuration JSON
     * @param deadline The latest timestamp this signature is valid for
     * @param serverSignature Signature from the server authorizing this game creation
     */
    function createGame(
        uint256 nonce,
        address token,
        uint256 betAmount,
        bytes32 gameSeedHash,
        bytes32 algorithm,
        bytes32 gameConfig,
        uint256 deadline,
        bytes calldata serverSignature
    ) external payable nonReentrant {
        require(block.timestamp <= deadline, "Signature expired");
        require(betAmount > 0, "Bet amount must be positive");

        // Verify resolver signature and get resolver address
        bytes32 structHash = keccak256(
            abi.encode(
                CREATE_GAME_TYPEHASH, nonce, token, betAmount, gameSeedHash, algorithm, gameConfig, msg.sender, deadline
            )
        );
        bytes32 messageHash = _hashTypedDataV4(structHash);
        address resolver = _verifyAndGetResolver(messageHash, serverSignature);

        if (usedNonces[nonce]) {
            revert NonceAlreadyUsed(nonce);
        }

        // Handle asset transfer - goes to total pool
        if (token == ETH_ADDRESS) {
            require(msg.value == betAmount, "ETH amount mismatch");
        } else {
            require(msg.value == 0, "No ETH should be sent for token games");
            IERC20(token).safeTransferFrom(msg.sender, address(this), betAmount);
        }

        // Mark nonce as used
        usedNonces[nonce] = true;

        // Create game
        count += 1;

        games[count] = Game({
            player: msg.sender,
            resolver: resolver,
            token: token,
            betAmount: betAmount,
            gameSeedHash: gameSeedHash,
            status: GameStatus.Active,
            payoutAmount: 0,
            gameSeed: "",
            algorithm: algorithm,
            gameConfig: gameConfig,
            gameState: "",
            createdAt: block.timestamp
        });
        emit GameCreated(nonce, count, msg.sender, resolver, token, betAmount, gameSeedHash);
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
        require(payoutAmount > 0, "Payout must be positive");

        address playerAddress = game.player;
        address token = game.token;
        address resolver = game.resolver;

        // Verify authorization - resolver can resolve directly, others need resolver signature
        if (msg.sender != resolver) {
            require(block.timestamp <= deadline, "Signature expired");
            bytes32 structHash = keccak256(
                abi.encode(CASH_OUT_TYPEHASH, id, payoutAmount, gameState, keccak256(bytes(gameSeed)), deadline)
            );
            bytes32 messageHash = _hashTypedDataV4(structHash);
            address signingResolver = _verifyAndGetResolver(messageHash, serverSignature);
            require(signingResolver == resolver, "Only game resolver can resolve");
        }

        // Check resolver has sufficient balance
        if (balanceOf[resolver][token] < payoutAmount) {
            revert InsufficientContractBalance(token, payoutAmount, balanceOf[resolver][token]);
        }

        // Update game state
        game.status = GameStatus.Won;
        game.payoutAmount = payoutAmount;
        game.gameState = gameState;
        game.gameSeed = gameSeed;

        // Update balances - deduct from resolver, add bet amount to resolver (house edge)
        balanceOf[resolver][token] -= payoutAmount;
        balanceOf[resolver][token] += game.betAmount;

        // Transfer payout to player
        if (token == ETH_ADDRESS) {
            (bool success,) = payable(playerAddress).call{value: payoutAmount}("");
            if (!success) {
                revert PayoutFailed(id, token, payoutAmount);
            }
        } else {
            IERC20(token).safeTransfer(playerAddress, payoutAmount);
        }

        emit PayoutSent(id, resolver, token, payoutAmount, playerAddress);
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

        address gameResolver = game.resolver;

        // Verify authorization - resolver can resolve directly, others need resolver signature
        if (msg.sender != gameResolver) {
            require(block.timestamp <= deadline, "Signature expired");
            bytes32 structHash =
                keccak256(abi.encode(MARK_GAME_AS_LOST_TYPEHASH, id, gameState, keccak256(bytes(gameSeed)), deadline));
            bytes32 messageHash = _hashTypedDataV4(structHash);
            address signingResolver = _verifyAndGetResolver(messageHash, serverSignature);
            require(signingResolver == gameResolver, "Only game resolver can resolve");
        }

        // Update game state
        game.status = GameStatus.Lost;
        game.gameState = gameState;
        game.gameSeed = gameSeed;

        // Add bet amount to resolver's balance (house keeps the bet)
        balanceOf[gameResolver][game.token] += game.betAmount;

        emit GameLost(id, gameResolver);
    }

    // ♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣
    //                 RESOLVER MANAGEMENT
    // ♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣

    /**
     * @notice Deposit ETH as a resolver to provide liquidity for games
     */
    function depositETH() external payable {
        require(msg.value > 0, "Must send ETH");
        balanceOf[msg.sender][ETH_ADDRESS] += msg.value;
        emit Deposit(msg.sender, ETH_ADDRESS, msg.value);
    }

    /**
     * @notice Deposit ERC20 tokens as a resolver to provide liquidity for games
     * @param token Token address
     * @param amount Amount to deposit
     */
    function deposit(address token, uint256 amount) external {
        require(token != ETH_ADDRESS, "Use depositETH for ETH");
        require(amount > 0, "Amount must be positive");
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        balanceOf[msg.sender][token] += amount;
        emit Deposit(msg.sender, token, amount);
    }

    /**
     * @notice Withdraw ETH from resolver balance
     * @param amount The amount to withdraw
     */
    function withdrawETH(uint256 amount) external nonReentrant {
        require(amount > 0, "Amount must be positive");
        require(amount <= balanceOf[msg.sender][ETH_ADDRESS], "Insufficient balance");

        balanceOf[msg.sender][ETH_ADDRESS] -= amount;
        
        (bool success,) = payable(msg.sender).call{value: amount}("");
        require(success, "ETH withdrawal failed");

        emit Withdraw(msg.sender, ETH_ADDRESS, amount);
    }

    /**
     * @notice Withdraw ERC20 tokens from resolver balance
     * @param token Token address
     * @param amount The amount to withdraw
     */
    function withdraw(address token, uint256 amount) external nonReentrant {
        require(token != ETH_ADDRESS, "Use withdrawETH for ETH");
        require(amount > 0, "Amount must be positive");
        require(amount <= balanceOf[msg.sender][token], "Insufficient balance");

        balanceOf[msg.sender][token] -= amount;
        IERC20(token).safeTransfer(msg.sender, amount);

        emit Withdraw(msg.sender, token, amount);
    }

    // ♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣
    //                   RECEIVE FUNCTION
    // ♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣

    /**
     * @notice Receive function to accept direct ETH deposits (credited to sender as resolver)
     */
    receive() external payable {
        balanceOf[msg.sender][ETH_ADDRESS] += msg.value;
        emit Deposit(msg.sender, ETH_ADDRESS, msg.value);
    }

    // ♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣
    //                  INTERNAL FUNCTIONS
    // ♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣♠♥♦♣

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
}
