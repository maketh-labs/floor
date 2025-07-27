// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";

/**
 * @title SignedVault
 * @dev A deposit/withdrawal contract where users deposit with specific resolvers and need resolver signatures to withdraw
 *
 * Features:
 * - Deposits of ETH and ERC20 tokens to specific resolvers
 * - Resolver-authorized withdrawals using EIP-712 signatures
 * - Permit2 integration for gasless ERC20 approvals
 * - Nonce-based replay protection
 * - Resolver balance tracking to prevent over-withdrawals
 * - Decentralized resolver system (no global backend signer)
 */
contract SignedVault is
    Initializable,
    ReentrancyGuardUpgradeable,
    EIP712Upgradeable,
    UUPSUpgradeable,
    OwnableUpgradeable
{
    using SafeERC20 for IERC20;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Address representing ETH (0x0)
    address public constant ETH_ADDRESS = address(0);

    /// @notice Permit2 contract address
    ISignatureTransfer public immutable PERMIT2;

    /// @notice EIP-712 type hash for withdrawal authorization
    bytes32 public constant WITHDRAW_TYPEHASH =
        keccak256("Withdraw(address user,address token,uint256 amount,address resolver,uint256 deadline)");

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      STATE VARIABLES                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Mapping to track used signatures to prevent replay attacks
    mapping(bytes32 signatureHash => bool used) public usedSignatures;

    /// @notice Mapping of resolver balances by token
    mapping(address resolver => mapping(address token => uint256 balance)) public resolverBalanceOf;

    /// @notice Mapping to track deposits by hash for backend verification
    /// @dev Hash is created from keccak256(abi.encodePacked(user, nonce))
    mapping(bytes32 depositHash => uint256 amount) public deposits;

    // @notice Reserved slots for upgradeability
    uint256[49] private __gap; // 49 reserved slots (reduced by 1 for new mapping)

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Emitted when a user deposits funds
    event Deposit(address user, address token, uint256 amount, uint256 nonce);

    /// @notice Emitted when a user withdraws funds
    event Withdraw(address user, address token, uint256 amount);

    /// @notice Emitted when a resolver cancels a signature
    event SignatureCancelled(address resolver, bytes signature);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           ERRORS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    error SignatureAlreadyUsed(bytes32 signatureHash);
    error InvalidAmount(uint256 amount);
    error InvalidAsset();
    error InsufficientResolverBalance(address resolver, address token, uint256 required, uint256 available);
    error InvalidSignature();
    error SignatureExpired();
    error ETHTransferFailed();
    error InvalidResolver();
    error DuplicateDeposit(bytes32 depositHash);

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
        __EIP712_init("SignedVault", "1");
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     DEPOSIT FUNCTIONS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Deposit ETH into the contract
     * @param resolver Address of the resolver who will be responsible for this deposit
     * @param nonce User-provided nonce for deposit verification
     */
    function depositETH(address resolver, uint256 nonce) external payable {
        if (resolver == address(0)) revert InvalidResolver();

        // Create deposit hash from user address and nonce
        bytes32 depositHash = keccak256(abi.encodePacked(msg.sender, nonce));

        // Check for duplicate deposits
        if (deposits[depositHash] != 0) revert DuplicateDeposit(depositHash);

        // Store deposit for backend verification
        deposits[depositHash] = msg.value;

        resolverBalanceOf[resolver][ETH_ADDRESS] += msg.value;
        emit Deposit(msg.sender, ETH_ADDRESS, msg.value, nonce);
    }

    /**
     * @notice Deposit ERC20 tokens into the contract
     * @param token Token address
     * @param amount Amount to deposit
     * @param resolver Address of the resolver who will be responsible for this deposit
     * @param nonce User-provided nonce for deposit verification
     */
    function deposit(address token, uint256 amount, address resolver, uint256 nonce) external {
        if (token == ETH_ADDRESS) revert InvalidAsset();
        if (resolver == address(0)) revert InvalidResolver();

        // Create deposit hash from user address and nonce
        bytes32 depositHash = keccak256(abi.encodePacked(msg.sender, nonce));

        // Check for duplicate deposits
        if (deposits[depositHash] != 0) revert DuplicateDeposit(depositHash);

        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        // Store deposit for backend verification
        deposits[depositHash] = amount;

        resolverBalanceOf[resolver][token] += amount;
        emit Deposit(msg.sender, token, amount, nonce);
    }

    /**
     * @notice Deposit ERC20 tokens using Permit2 for gasless approvals
     * @param resolver Address of the resolver who will be responsible for this deposit
     * @param permit Permit2 permit data signed by the user
     * @param signature User's signature for the Permit2 transfer
     * @param nonce User-provided nonce for deposit verification
     */
    function depositWithPermit2(
        address resolver,
        ISignatureTransfer.PermitTransferFrom memory permit,
        bytes calldata signature,
        uint256 nonce
    ) external {
        address token = permit.permitted.token;
        uint256 amount = permit.permitted.amount;

        if (token == ETH_ADDRESS) revert InvalidAsset();
        if (resolver == address(0)) revert InvalidResolver();

        // Create deposit hash from user address and nonce
        bytes32 depositHash = keccak256(abi.encodePacked(msg.sender, nonce));

        // Check for duplicate deposits
        if (deposits[depositHash] != 0) revert DuplicateDeposit(depositHash);

        // Create transfer details - use full permitted amount
        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            ISignatureTransfer.SignatureTransferDetails({to: address(this), requestedAmount: amount});

        // Transfer tokens using Permit2
        PERMIT2.permitTransferFrom(permit, transferDetails, msg.sender, signature);

        // Store deposit for backend verification
        deposits[depositHash] = amount;

        resolverBalanceOf[resolver][token] += amount;
        emit Deposit(msg.sender, token, amount, nonce);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    SIGNATURE MANAGEMENT                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Cancel a signature to prevent its future use
     * @dev Anyone can cancel any signature by providing it
     * @param signature The signature to cancel
     */
    function cancelSignature(bytes calldata signature) external {
        // Mark the signature hash as used to prevent its future use
        bytes32 signatureHash = keccak256(signature);
        usedSignatures[signatureHash] = true;

        emit SignatureCancelled(msg.sender, signature);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    WITHDRAWAL FUNCTIONS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Withdraw ETH from the contract (requires resolver signature)
     * @param user Address of the user to withdraw to
     * @param amount Amount to withdraw
     * @param resolver Address of the resolver authorizing this withdrawal
     * @param deadline Latest timestamp this signature is valid for
     * @param signature Resolver signature authorizing this withdrawal
     */
    function withdrawETH(address user, uint256 amount, address resolver, uint256 deadline, bytes calldata signature)
        external
        nonReentrant
    {
        _withdraw(user, ETH_ADDRESS, amount, resolver, deadline, signature);
    }

    /**
     * @notice Withdraw ERC20 tokens from the contract (requires resolver signature)
     * @param user Address of the user to withdraw to
     * @param token Token address
     * @param amount Amount to withdraw
     * @param resolver Address of the resolver authorizing this withdrawal
     * @param deadline Latest timestamp this signature is valid for
     * @param signature Resolver signature authorizing this withdrawal
     */
    function withdraw(
        address user,
        address token,
        uint256 amount,
        address resolver,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant {
        if (token == ETH_ADDRESS) revert InvalidAsset();
        _withdraw(user, token, amount, resolver, deadline, signature);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    INTERNAL FUNCTIONS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @dev Internal function to handle withdrawals with signature verification
     * @param user User address
     * @param token Token address (ETH_ADDRESS for ETH)
     * @param amount Amount to withdraw
     * @param resolver Address of the resolver authorizing withdrawal
     * @param deadline Signature deadline, doubles as nonce
     * @param signature Resolver signature
     */
    function _withdraw(
        address user,
        address token,
        uint256 amount,
        address resolver,
        uint256 deadline,
        bytes calldata signature
    ) internal {
        if (block.timestamp > deadline) revert SignatureExpired();
        if (amount == 0) revert InvalidAmount(amount);
        if (resolver == address(0)) revert InvalidResolver();

        // Verify resolver signature
        bytes32 messageHash =
            _hashTypedDataV4(keccak256(abi.encode(WITHDRAW_TYPEHASH, user, token, amount, resolver, deadline)));

        // Check if signature has been used before (includes cancelled signatures)
        bytes32 signatureHash = keccak256(signature);
        if (usedSignatures[signatureHash]) revert SignatureAlreadyUsed(signatureHash);

        // Check resolver has sufficient balance
        uint256 resolverBalance = resolverBalanceOf[resolver][token];
        if (resolverBalance < amount) {
            revert InsufficientResolverBalance(resolver, token, amount, resolverBalance);
        }

        address recoveredSigner = ECDSA.recover(messageHash, signature);
        if (recoveredSigner == address(0) || recoveredSigner != resolver) {
            revert InvalidSignature();
        }

        // Mark signature as used
        usedSignatures[signatureHash] = true;

        // Deduct from resolver's balance
        resolverBalanceOf[resolver][token] -= amount;

        // Transfer assets
        if (token == ETH_ADDRESS) {
            (bool success,) = payable(user).call{value: amount}("");
            if (!success) revert ETHTransferFailed();
        } else {
            IERC20(token).safeTransfer(user, amount);
        }

        emit Withdraw(user, token, amount);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       VIEW FUNCTIONS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Get a resolver's balance for a specific token
     * @param resolver Resolver address
     * @param token Token address (ETH_ADDRESS for ETH)
     * @return balance Resolver's balance
     */
    function getResolverBalance(address resolver, address token) external view returns (uint256 balance) {
        return resolverBalanceOf[resolver][token];
    }

    /**
     * @notice Get deposit amount by hash for backend verification
     * @param user User address
     * @param nonce User-provided nonce
     * @return amount Deposit amount (0 if not found)
     */
    function getDepositByHash(address user, uint256 nonce) external view returns (uint256 amount) {
        bytes32 depositHash = keccak256(abi.encodePacked(user, nonce));
        return deposits[depositHash];
    }

    /**
     * @notice Create deposit hash from user address and nonce
     * @param user User address
     * @param nonce User-provided nonce
     * @return depositHash The hash used as deposit key
     */
    function createDepositHash(address user, uint256 nonce) external pure returns (bytes32 depositHash) {
        return keccak256(abi.encodePacked(user, nonce));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    UPGRADE AUTHORIZATION                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
