// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {CommitReveal} from "../src/CommitReveal.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";
import {DeployPermit2} from "permit2/test/utils/DeployPermit2.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract CommitRevealTest is Test, DeployPermit2 {
    CommitReveal public commitReveal;
    ERC20Mock public token;
    ISignatureTransfer public permit2;

    // Test accounts
    address public player;
    address public resolver;

    // Private key for signing
    uint256 public resolverPrivateKey;
    uint256 public playerPrivateKey;

    // Test constants
    uint256 public constant BET_AMOUNT = 1 ether;
    uint256 public constant LARGE_DEPOSIT = 1000 * 10 ** 18;
    uint256 public constant SMALL_DEPOSIT = 10 * 10 ** 18;
    bytes32 public constant GAME_SEED_HASH = keccak256("test_seed");
    bytes32 public constant ALGORITHM = bytes32("QmTestAlgorithm");
    bytes32 public constant GAME_CONFIG = bytes32("QmTestGameConfig");
    bytes32 public constant SALT = keccak256("user_entropy_salt");
    bytes32 public constant GAME_STATE = bytes32("QmState");
    bytes32 public constant LOST_STATE = bytes32("QmLost");

    // EIP712 domain separator for testing
    bytes32 public domainSeparator;
    bytes32 public permit2DomainSeparator;

    // Type hashes
    bytes32 public constant CREATE_GAME_TYPEHASH = keccak256(
        "CreateGame(address token,uint256 betAmount,bytes32 gameSeedHash,bytes32 algorithm,bytes32 gameConfig,address player,uint256 deadline)"
    );

    bytes32 public constant PERMIT_TRANSFER_FROM_TYPEHASH = keccak256(
        "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
    );

    function setUp() public {
        // Deploy actual Permit2 contract
        permit2 = ISignatureTransfer(deployPermit2());

        // Deploy CommitReveal implementation
        CommitReveal implementation = new CommitReveal(address(permit2));

        // Deploy proxy with initialization
        bytes memory initData = abi.encodeWithSelector(
            CommitReveal.initialize.selector,
            address(this) // owner
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        commitReveal = CommitReveal(payable(address(proxy)));

        token = new ERC20Mock();

        // Set up resolver account
        (resolver, resolverPrivateKey) = makeAddrAndKey("resolver");

        // Set up player account
        (player, playerPrivateKey) = makeAddrAndKey("player");

        // Fund test accounts
        vm.deal(player, 10 ether);
        vm.deal(resolver, 10 ether);

        // Give tokens to player and resolver
        token.mint(player, 1000 * 10 ** 18);
        token.mint(resolver, 1000 * 10 ** 18);

        // Approve Permit2 to spend tokens
        vm.prank(player);
        token.approve(address(permit2), type(uint256).max);

        // Compute domain separators
        domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("CommitReveal"),
                keccak256("1"),
                block.chainid,
                address(commitReveal)
            )
        );

        // Get actual Permit2 domain separator
        permit2DomainSeparator = permit2.DOMAIN_SEPARATOR();
    }

    // Helper function to create game signatures
    function createGameSignature(CommitReveal.CreateGameParams memory params, address playerAddr)
        internal
        view
        returns (bytes memory)
    {
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(
                    abi.encode(
                        CREATE_GAME_TYPEHASH,
                        params.token,
                        params.betAmount,
                        params.gameSeedHash,
                        params.algorithm,
                        params.gameConfig,
                        playerAddr,
                        params.deadline
                    )
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(resolverPrivateKey, messageHash);
        return abi.encodePacked(r, s, v);
    }

    // Helper function to create Permit2 signatures
    function createPermit2Signature(
        address tokenAddress,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        address spender
    ) internal view returns (bytes memory) {
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                permit2DomainSeparator,
                keccak256(
                    abi.encode(
                        PERMIT_TRANSFER_FROM_TYPEHASH,
                        keccak256(
                            abi.encode(
                                keccak256("TokenPermissions(address token,uint256 amount)"), tokenAddress, amount
                            )
                        ),
                        spender,
                        nonce,
                        deadline
                    )
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPrivateKey, messageHash);
        return abi.encodePacked(r, s, v);
    }

    // Helper to create resolver signatures for cashOut
    function createCashOutSignature(
        bytes32 gameId,
        uint256 payoutAmount,
        bytes32 gameState,
        bytes32 gameSeed,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(
                    abi.encode(commitReveal.CASH_OUT_TYPEHASH(), gameId, payoutAmount, gameState, gameSeed, deadline)
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(resolverPrivateKey, messageHash);
        return abi.encodePacked(r, s, v);
    }

    // Helper to create resolver signatures for markGameAsLost
    function createMarkLostSignature(bytes32 gameId, bytes32 gameState, bytes32 gameSeed, uint256 deadline)
        internal
        view
        returns (bytes memory)
    {
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(abi.encode(commitReveal.MARK_GAME_AS_LOST_TYPEHASH(), gameId, gameState, gameSeed, deadline))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(resolverPrivateKey, messageHash);
        return abi.encodePacked(r, s, v);
    }

    // Helper function to setup resolver with token deposits
    function setupResolverWithTokens(uint256 depositAmount) internal {
        vm.prank(resolver);
        token.approve(address(commitReveal), depositAmount);
        vm.prank(resolver);
        commitReveal.deposit(address(token), depositAmount);
    }

    // Helper function to create and fund a game
    function createTokenGame(uint256 betAmount) internal returns (bytes32 gameId, bytes memory signature) {
        uint256 deadline = block.timestamp + 1 hours;

        CommitReveal.CreateGameParams memory params = CommitReveal.CreateGameParams({
            token: address(token),
            betAmount: betAmount,
            gameSeedHash: GAME_SEED_HASH,
            algorithm: ALGORITHM,
            gameConfig: GAME_CONFIG,
            deadline: deadline
        });

        signature = createGameSignature(params, player);
        gameId = keccak256(signature);

        vm.prank(player);
        token.approve(address(commitReveal), betAmount);
        vm.prank(player);
        commitReveal.createGame(params, signature, SALT);
    }

    // ============ BASIC TESTS ============

    function testConstructor() public view {
        // Test that the contract is properly initialized
        assertEq(commitReveal.ETH_ADDRESS(), address(0));
    }

    function testConstants() public view {
        // Test that all constants are properly set
        assertEq(commitReveal.ETH_ADDRESS(), address(0));
        assertNotEq(commitReveal.CREATE_GAME_TYPEHASH(), bytes32(0));
        assertNotEq(commitReveal.CASH_OUT_TYPEHASH(), bytes32(0));
        assertNotEq(commitReveal.MARK_GAME_AS_LOST_TYPEHASH(), bytes32(0));
    }

    // ============ RESOLVER MANAGEMENT TESTS ============

    function testDepositETH() public {
        uint256 depositAmount = 5 ether;

        vm.prank(resolver);
        commitReveal.depositETH{value: depositAmount}();

        assertEq(commitReveal.balanceOf(resolver, commitReveal.ETH_ADDRESS()), depositAmount);
    }

    function testDepositERC20() public {
        uint256 depositAmount = 1000 * 10 ** 18;

        vm.prank(resolver);
        token.approve(address(commitReveal), depositAmount);

        vm.prank(resolver);
        commitReveal.deposit(address(token), depositAmount);

        assertEq(commitReveal.balanceOf(resolver, address(token)), depositAmount);
    }

    function testWithdrawETH() public {
        uint256 depositAmount = 5 ether;
        uint256 withdrawAmount = 2 ether;

        // Deposit first
        vm.prank(resolver);
        commitReveal.depositETH{value: depositAmount}();

        uint256 balanceBefore = resolver.balance;

        vm.prank(resolver);
        commitReveal.withdrawETH(withdrawAmount);

        assertEq(resolver.balance, balanceBefore + withdrawAmount);
        assertEq(commitReveal.balanceOf(resolver, commitReveal.ETH_ADDRESS()), depositAmount - withdrawAmount);
    }

    function testWithdrawERC20() public {
        uint256 depositAmount = 1000 * 10 ** 18;
        uint256 withdrawAmount = 500 * 10 ** 18;

        // Deposit first
        vm.prank(resolver);
        token.approve(address(commitReveal), depositAmount);
        vm.prank(resolver);
        commitReveal.deposit(address(token), depositAmount);

        uint256 balanceBefore = token.balanceOf(resolver);

        vm.prank(resolver);
        commitReveal.withdraw(address(token), withdrawAmount);

        assertEq(token.balanceOf(resolver), balanceBefore + withdrawAmount);
        assertEq(commitReveal.balanceOf(resolver, address(token)), depositAmount - withdrawAmount);
    }

    // ============ GAME CREATION TESTS ============

    function testCreateGameETH() public {
        uint256 deadline = block.timestamp + 1 hours;

        CommitReveal.CreateGameParams memory params = CommitReveal.CreateGameParams({
            token: address(0), // ETH
            betAmount: BET_AMOUNT,
            gameSeedHash: GAME_SEED_HASH,
            algorithm: ALGORITHM,
            gameConfig: GAME_CONFIG,
            deadline: deadline
        });

        bytes memory signature = createGameSignature(params, player);

        vm.prank(player);
        commitReveal.createGame{value: BET_AMOUNT}(params, signature, SALT);

        // Verify game was created correctly
        assertTrue(commitReveal.usedSignatures(keccak256(signature)));
    }

    // ============ PERMIT2 TESTS ============

    function testCreateGameWithPermit2() public {
        uint256 deadline = block.timestamp + 1 hours;
        uint256 permit2Nonce = 0;
        uint256 betAmount = 100 * 10 ** 18;

        CommitReveal.CreateGameParams memory params = CommitReveal.CreateGameParams({
            token: address(token),
            betAmount: betAmount,
            gameSeedHash: GAME_SEED_HASH,
            algorithm: ALGORITHM,
            gameConfig: GAME_CONFIG,
            deadline: deadline
        });

        bytes memory signature = createGameSignature(params, player);

        // Create Permit2 permit
        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({token: address(token), amount: betAmount}),
            nonce: permit2Nonce,
            deadline: deadline
        });

        // Create transfer details
        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            ISignatureTransfer.SignatureTransferDetails({to: address(commitReveal), requestedAmount: betAmount});

        bytes memory permitSignature =
            createPermit2Signature(address(token), betAmount, permit2Nonce, deadline, address(commitReveal));

        vm.prank(player);
        commitReveal.createGameWithPermit2(params, signature, SALT, permit, transferDetails, permitSignature);

        // Verify game was created correctly
        assertTrue(commitReveal.usedSignatures(keccak256(signature)));

        // Verify tokens were transferred
        assertEq(token.balanceOf(address(commitReveal)), betAmount);
    }

    function testCreateGameWithPermit2TokenMismatch() public {
        uint256 deadline = block.timestamp + 1 hours;
        uint256 permit2Nonce = 0;
        uint256 betAmount = 100 * 10 ** 18;

        // Create different token for mismatch test
        ERC20Mock differentToken = new ERC20Mock();
        differentToken.mint(player, 1000 * 10 ** 18);

        CommitReveal.CreateGameParams memory params = CommitReveal.CreateGameParams({
            token: address(token), // Using original token
            betAmount: betAmount,
            gameSeedHash: GAME_SEED_HASH,
            algorithm: ALGORITHM,
            gameConfig: GAME_CONFIG,
            deadline: deadline
        });

        bytes memory signature = createGameSignature(params, player);

        // Create Permit2 permit with different token
        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: address(differentToken), // Using different token
                amount: betAmount
            }),
            nonce: permit2Nonce,
            deadline: deadline
        });

        // Create transfer details
        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            ISignatureTransfer.SignatureTransferDetails({to: address(commitReveal), requestedAmount: betAmount});

        bytes memory permitSignature =
            createPermit2Signature(address(differentToken), betAmount, permit2Nonce, deadline, address(commitReveal));

        vm.prank(player);
        vm.expectRevert(CommitReveal.TokenMismatch.selector);
        commitReveal.createGameWithPermit2(params, signature, SALT, permit, transferDetails, permitSignature);
    }

    function testCreateGameWithPermit2InsufficientAmount() public {
        uint256 deadline = block.timestamp + 1 hours;
        uint256 permit2Nonce = 0;
        uint256 betAmount = 100 * 10 ** 18;
        uint256 permitAmount = 50 * 10 ** 18; // Less than bet amount

        CommitReveal.CreateGameParams memory params = CommitReveal.CreateGameParams({
            token: address(token),
            betAmount: betAmount,
            gameSeedHash: GAME_SEED_HASH,
            algorithm: ALGORITHM,
            gameConfig: GAME_CONFIG,
            deadline: deadline
        });

        bytes memory signature = createGameSignature(params, player);

        // Create Permit2 permit with insufficient amount
        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: address(token),
                amount: permitAmount // Less than bet amount
            }),
            nonce: permit2Nonce,
            deadline: deadline
        });

        // Create transfer details
        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            ISignatureTransfer.SignatureTransferDetails({to: address(commitReveal), requestedAmount: betAmount});

        bytes memory permitSignature =
            createPermit2Signature(address(token), permitAmount, permit2Nonce, deadline, address(commitReveal));

        vm.prank(player);
        vm.expectRevert(CommitReveal.InsufficientPermitAmount.selector);
        commitReveal.createGameWithPermit2(params, signature, SALT, permit, transferDetails, permitSignature);
    }

    function testCreateGameWithPermit2ExpiredDeadline() public {
        // Set a proper timestamp to avoid underflow
        vm.warp(2 hours);

        uint256 deadline = block.timestamp - 1 hours; // Now this won't underflow
        uint256 permit2Nonce = 0;
        uint256 betAmount = 100 * 10 ** 18;

        CommitReveal.CreateGameParams memory params = CommitReveal.CreateGameParams({
            token: address(token),
            betAmount: betAmount,
            gameSeedHash: GAME_SEED_HASH,
            algorithm: ALGORITHM,
            gameConfig: GAME_CONFIG,
            deadline: deadline
        });

        bytes memory signature = createGameSignature(params, player);

        // Create Permit2 permit
        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({token: address(token), amount: betAmount}),
            nonce: permit2Nonce,
            deadline: deadline
        });

        // Create transfer details
        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            ISignatureTransfer.SignatureTransferDetails({to: address(commitReveal), requestedAmount: betAmount});

        bytes memory permitSignature =
            createPermit2Signature(address(token), betAmount, permit2Nonce, deadline, address(commitReveal));

        vm.prank(player);
        vm.expectRevert(CommitReveal.SignatureExpired.selector);
        commitReveal.createGameWithPermit2(params, signature, SALT, permit, transferDetails, permitSignature);
    }

    function testCreateGameWithPermit2NonceReuse() public {
        uint256 deadline = block.timestamp + 1 hours;
        uint256 permit2Nonce = 0;
        uint256 betAmount = 100 * 10 ** 18;

        CommitReveal.CreateGameParams memory params = CommitReveal.CreateGameParams({
            token: address(token),
            betAmount: betAmount,
            gameSeedHash: GAME_SEED_HASH,
            algorithm: ALGORITHM,
            gameConfig: GAME_CONFIG,
            deadline: deadline
        });

        bytes memory signature = createGameSignature(params, player);

        // Create Permit2 permit
        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({token: address(token), amount: betAmount}),
            nonce: permit2Nonce,
            deadline: deadline
        });

        // Create transfer details
        ISignatureTransfer.SignatureTransferDetails memory transferDetails =
            ISignatureTransfer.SignatureTransferDetails({to: address(commitReveal), requestedAmount: betAmount});

        bytes memory permitSignature =
            createPermit2Signature(address(token), betAmount, permit2Nonce, deadline, address(commitReveal));

        // First call should succeed
        vm.prank(player);
        commitReveal.createGameWithPermit2(params, signature, SALT, permit, transferDetails, permitSignature);

        // Second call with same nonce should fail
        vm.prank(player);
        vm.expectRevert(abi.encodeWithSelector(CommitReveal.SignatureAlreadyUsed.selector, keccak256(signature)));
        commitReveal.createGameWithPermit2(params, signature, SALT, permit, transferDetails, permitSignature);
    }

    function testCreateGameWithPermit2InvalidTransferDestination() public {
        uint256 deadline = block.timestamp + 1 hours;
        uint256 permit2Nonce = 0;
        uint256 betAmount = 100 * 10 ** 18;

        CommitReveal.CreateGameParams memory params = CommitReveal.CreateGameParams({
            token: address(token),
            betAmount: betAmount,
            gameSeedHash: GAME_SEED_HASH,
            algorithm: ALGORITHM,
            gameConfig: GAME_CONFIG,
            deadline: deadline
        });

        bytes memory signature = createGameSignature(params, player);

        // Create Permit2 permit
        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({token: address(token), amount: betAmount}),
            nonce: permit2Nonce,
            deadline: deadline
        });

        // Create transfer details with wrong destination
        ISignatureTransfer.SignatureTransferDetails memory transferDetails = ISignatureTransfer.SignatureTransferDetails({
            to: address(0x1234), // Wrong destination
            requestedAmount: betAmount
        });

        bytes memory permitSignature = createPermit2Signature(
            address(token),
            betAmount,
            permit2Nonce,
            deadline,
            address(0x1234) // Wrong destination
        );

        vm.prank(player);
        vm.expectRevert(CommitReveal.InvalidPermitTransfer.selector);
        commitReveal.createGameWithPermit2(params, signature, SALT, permit, transferDetails, permitSignature);
    }

    function testCreateGameWithPermit2InvalidRequestedAmount() public {
        uint256 deadline = block.timestamp + 1 hours;
        uint256 permit2Nonce = 0;
        uint256 betAmount = 100 * 10 ** 18;
        uint256 wrongAmount = 50 * 10 ** 18; // Different from bet amount

        CommitReveal.CreateGameParams memory params = CommitReveal.CreateGameParams({
            token: address(token),
            betAmount: betAmount,
            gameSeedHash: GAME_SEED_HASH,
            algorithm: ALGORITHM,
            gameConfig: GAME_CONFIG,
            deadline: deadline
        });

        bytes memory signature = createGameSignature(params, player);

        // Create Permit2 permit with sufficient amount
        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: address(token),
                amount: betAmount // Sufficient amount
            }),
            nonce: permit2Nonce,
            deadline: deadline
        });

        // Create transfer details with wrong requested amount
        ISignatureTransfer.SignatureTransferDetails memory transferDetails = ISignatureTransfer.SignatureTransferDetails({
            to: address(commitReveal),
            requestedAmount: wrongAmount // Different from bet amount
        });

        bytes memory permitSignature =
            createPermit2Signature(address(token), betAmount, permit2Nonce, deadline, address(commitReveal));

        vm.prank(player);
        vm.expectRevert(abi.encodeWithSelector(CommitReveal.InvalidAmount.selector, wrongAmount));
        commitReveal.createGameWithPermit2(params, signature, SALT, permit, transferDetails, permitSignature);
    }

    function testCreateGameETHNonceReuse() public {
        uint256 deadline = block.timestamp + 1 hours;

        CommitReveal.CreateGameParams memory params = CommitReveal.CreateGameParams({
            token: address(0),
            betAmount: BET_AMOUNT,
            gameSeedHash: GAME_SEED_HASH,
            algorithm: ALGORITHM,
            gameConfig: GAME_CONFIG,
            deadline: deadline
        });

        bytes memory signature = createGameSignature(params, player);

        vm.prank(player);
        commitReveal.createGame{value: BET_AMOUNT}(params, signature, SALT);

        vm.prank(player);
        vm.expectRevert(abi.encodeWithSelector(CommitReveal.SignatureAlreadyUsed.selector, keccak256(signature)));
        commitReveal.createGame{value: BET_AMOUNT}(params, signature, SALT);
    }

    function testCashOutByResolver() public {
        uint256 depositAmount = LARGE_DEPOSIT;
        uint256 betAmount = 100 * 10 ** 18;

        setupResolverWithTokens(depositAmount);
        (bytes32 gameId,) = createTokenGame(betAmount);

        uint256 payoutAmount = 50 * 10 ** 18;
        bytes32 gameSeed = keccak256("seed1");

        uint256 playerBalanceBefore = token.balanceOf(player);
        vm.prank(resolver);
        commitReveal.cashOut(gameId, payoutAmount, GAME_STATE, gameSeed, 0, "");

        assertEq(token.balanceOf(player), playerBalanceBefore + payoutAmount);
        assertEq(commitReveal.balanceOf(resolver, address(token)), depositAmount - payoutAmount + betAmount);
    }

    function testCashOutByPlayerWithSignature() public {
        uint256 depositAmount = LARGE_DEPOSIT;
        uint256 betAmount = 100 * 10 ** 18;

        setupResolverWithTokens(depositAmount);
        (bytes32 gameId,) = createTokenGame(betAmount);

        uint256 payoutAmount = 60 * 10 ** 18;
        bytes32 gameSeed = keccak256("seed2");

        uint256 sigDeadline = block.timestamp + 1 hours;
        bytes memory cashSig = createCashOutSignature(gameId, payoutAmount, GAME_STATE, gameSeed, sigDeadline);

        uint256 playerBalanceBefore = token.balanceOf(player);
        vm.prank(player);
        commitReveal.cashOut(gameId, payoutAmount, GAME_STATE, gameSeed, sigDeadline, cashSig);

        assertEq(token.balanceOf(player), playerBalanceBefore + payoutAmount);
        assertEq(commitReveal.balanceOf(resolver, address(token)), depositAmount - payoutAmount + betAmount);
    }

    function testCashOutInsufficientBalance() public {
        uint256 depositAmount = SMALL_DEPOSIT;
        uint256 betAmount = 5 * 10 ** 18;

        setupResolverWithTokens(depositAmount);
        (bytes32 gameId,) = createTokenGame(betAmount);

        uint256 payoutAmount = 20 * 10 ** 18;

        vm.prank(resolver);
        vm.expectRevert(
            abi.encodeWithSelector(
                CommitReveal.InsufficientContractBalance.selector,
                address(token),
                payoutAmount,
                depositAmount + betAmount
            )
        );
        commitReveal.cashOut(gameId, payoutAmount, GAME_STATE, keccak256("seed"), 0, "");
    }

    function testMarkGameAsLostByResolver() public {
        uint256 depositAmount = LARGE_DEPOSIT;
        uint256 betAmount = 100 * 10 ** 18;

        setupResolverWithTokens(depositAmount);
        (bytes32 gameId,) = createTokenGame(betAmount);

        bytes32 gameSeed = keccak256("lost");

        vm.prank(resolver);
        commitReveal.markGameAsLost(gameId, LOST_STATE, gameSeed, 0, "");

        assertEq(commitReveal.balanceOf(resolver, address(token)), depositAmount + betAmount);
    }

    function testMarkGameAsLostByPlayerWithSignature() public {
        uint256 depositAmount = 500 * 10 ** 18;
        uint256 betAmount = 50 * 10 ** 18;

        setupResolverWithTokens(depositAmount);
        (bytes32 gameId,) = createTokenGame(betAmount);

        bytes32 gameSeed = keccak256("lost2");

        uint256 sigDeadline = block.timestamp + 1 hours;
        bytes memory sigLost = createMarkLostSignature(gameId, LOST_STATE, gameSeed, sigDeadline);

        vm.prank(player);
        commitReveal.markGameAsLost(gameId, LOST_STATE, gameSeed, sigDeadline, sigLost);

        assertEq(commitReveal.balanceOf(resolver, address(token)), depositAmount + betAmount);
    }

    function testDepositInvalidAmount() public {
        vm.prank(resolver);
        vm.expectRevert(abi.encodeWithSelector(CommitReveal.InvalidAmount.selector, 0));
        commitReveal.deposit(address(token), 0);
    }

    function testDepositInvalidAsset() public {
        vm.prank(resolver);
        vm.expectRevert(CommitReveal.InvalidAsset.selector);
        commitReveal.deposit(address(0), 1);
    }
}
