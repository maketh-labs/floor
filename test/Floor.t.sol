// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {Floor} from "../src/Floor.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";
import {DeployPermit2} from "permit2/test/utils/DeployPermit2.sol";

contract FloorTest is Test, DeployPermit2 {
    Floor public floor;
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
    bytes32 public constant GAME_SEED_HASH = keccak256("test_seed");
    bytes32 public constant ALGORITHM = bytes32("QmTestAlgorithm");
    bytes32 public constant GAME_CONFIG = bytes32("QmTestGameConfig");

    // EIP712 domain separator for testing
    bytes32 public domainSeparator;
    bytes32 public permit2DomainSeparator;

    // Type hashes
    bytes32 public constant CREATE_GAME_TYPEHASH = keccak256(
        "CreateGame(uint256 nonce,address token,uint256 betAmount,bytes32 gameSeedHash,bytes32 algorithm,bytes32 gameConfig,address player,uint256 deadline)"
    );

    bytes32 public constant PERMIT_TRANSFER_FROM_TYPEHASH = keccak256(
        "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
    );

    function setUp() public {
        // Deploy actual Permit2 contract
        permit2 = ISignatureTransfer(deployPermit2());

        // Deploy Floor with actual Permit2
        floor = new Floor(address(permit2));
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
                keccak256("Floor"),
                keccak256("1"),
                block.chainid,
                address(floor)
            )
        );

        // Get actual Permit2 domain separator
        permit2DomainSeparator = permit2.DOMAIN_SEPARATOR();
    }

    // Helper function to create game signatures
    function createGameSignature(Floor.CreateGameParams memory params, address playerAddr)
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
                        params.nonce,
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

    // ============ BASIC TESTS ============

    function testConstructor() public {
        // Test that the contract is properly initialized
        assertEq(floor.count(), 0);
        assertEq(floor.ETH_ADDRESS(), address(0));
    }

    function testConstants() public {
        // Test that all constants are properly set
        assertEq(floor.ETH_ADDRESS(), address(0));
        assertNotEq(floor.CREATE_GAME_TYPEHASH(), bytes32(0));
        assertNotEq(floor.CASH_OUT_TYPEHASH(), bytes32(0));
        assertNotEq(floor.MARK_GAME_AS_LOST_TYPEHASH(), bytes32(0));
    }

    // ============ RESOLVER MANAGEMENT TESTS ============

    function testDepositETH() public {
        uint256 depositAmount = 5 ether;

        vm.prank(resolver);
        floor.depositETH{value: depositAmount}();

        assertEq(floor.balanceOf(resolver, floor.ETH_ADDRESS()), depositAmount);
    }

    function testDepositERC20() public {
        uint256 depositAmount = 1000 * 10 ** 18;

        vm.prank(resolver);
        token.approve(address(floor), depositAmount);

        vm.prank(resolver);
        floor.deposit(address(token), depositAmount);

        assertEq(floor.balanceOf(resolver, address(token)), depositAmount);
    }

    function testWithdrawETH() public {
        uint256 depositAmount = 5 ether;
        uint256 withdrawAmount = 2 ether;

        // Deposit first
        vm.prank(resolver);
        floor.depositETH{value: depositAmount}();

        uint256 balanceBefore = resolver.balance;

        vm.prank(resolver);
        floor.withdrawETH(withdrawAmount);

        assertEq(resolver.balance, balanceBefore + withdrawAmount);
        assertEq(floor.balanceOf(resolver, floor.ETH_ADDRESS()), depositAmount - withdrawAmount);
    }

    function testWithdrawERC20() public {
        uint256 depositAmount = 1000 * 10 ** 18;
        uint256 withdrawAmount = 500 * 10 ** 18;

        // Deposit first
        vm.prank(resolver);
        token.approve(address(floor), depositAmount);
        vm.prank(resolver);
        floor.deposit(address(token), depositAmount);

        uint256 balanceBefore = token.balanceOf(resolver);

        vm.prank(resolver);
        floor.withdraw(address(token), withdrawAmount);

        assertEq(token.balanceOf(resolver), balanceBefore + withdrawAmount);
        assertEq(floor.balanceOf(resolver, address(token)), depositAmount - withdrawAmount);
    }

    // ============ GAME CREATION TESTS ============

    function testCreateGameETH() public {
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 1 hours;

        Floor.CreateGameParams memory params = Floor.CreateGameParams({
            nonce: nonce,
            token: address(0), // ETH
            betAmount: BET_AMOUNT,
            gameSeedHash: GAME_SEED_HASH,
            algorithm: ALGORITHM,
            gameConfig: GAME_CONFIG,
            deadline: deadline
        });

        bytes memory signature = createGameSignature(params, player);

        vm.prank(player);
        floor.createGame{value: BET_AMOUNT}(params, signature);

        // Verify game was created correctly
        assertEq(floor.count(), 1);
        assertTrue(floor.usedNonces(nonce));
    }

    // ============ PERMIT2 TESTS ============

    function testCreateGameWithPermit2() public {
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 permit2Nonce = 0;
        uint256 betAmount = 100 * 10 ** 18;

        Floor.CreateGameParams memory params = Floor.CreateGameParams({
            nonce: nonce,
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
            ISignatureTransfer.SignatureTransferDetails({to: address(floor), requestedAmount: betAmount});

        bytes memory permitSignature =
            createPermit2Signature(address(token), betAmount, permit2Nonce, deadline, address(floor));

        vm.prank(player);
        floor.createGameWithPermit2(params, signature, permit, transferDetails, permitSignature);

        // Verify game was created correctly
        assertEq(floor.count(), 1);
        assertTrue(floor.usedNonces(nonce));

        // Verify tokens were transferred
        assertEq(token.balanceOf(address(floor)), betAmount);
    }

    function testCreateGameWithPermit2TokenMismatch() public {
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 permit2Nonce = 0;
        uint256 betAmount = 100 * 10 ** 18;

        // Create different token for mismatch test
        ERC20Mock differentToken = new ERC20Mock();
        differentToken.mint(player, 1000 * 10 ** 18);

        Floor.CreateGameParams memory params = Floor.CreateGameParams({
            nonce: nonce,
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
            ISignatureTransfer.SignatureTransferDetails({to: address(floor), requestedAmount: betAmount});

        bytes memory permitSignature =
            createPermit2Signature(address(differentToken), betAmount, permit2Nonce, deadline, address(floor));

        vm.prank(player);
        vm.expectRevert(Floor.TokenMismatch.selector);
        floor.createGameWithPermit2(params, signature, permit, transferDetails, permitSignature);
    }

    function testCreateGameWithPermit2InsufficientAmount() public {
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 permit2Nonce = 0;
        uint256 betAmount = 100 * 10 ** 18;
        uint256 permitAmount = 50 * 10 ** 18; // Less than bet amount

        Floor.CreateGameParams memory params = Floor.CreateGameParams({
            nonce: nonce,
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
            ISignatureTransfer.SignatureTransferDetails({to: address(floor), requestedAmount: betAmount});

        bytes memory permitSignature =
            createPermit2Signature(address(token), permitAmount, permit2Nonce, deadline, address(floor));

        vm.prank(player);
        vm.expectRevert(Floor.InsufficientPermitAmount.selector);
        floor.createGameWithPermit2(params, signature, permit, transferDetails, permitSignature);
    }

    function testCreateGameWithPermit2ExpiredDeadline() public {
        // Set a proper timestamp to avoid underflow
        vm.warp(2 hours);

        uint256 nonce = 1;
        uint256 deadline = block.timestamp - 1 hours; // Now this won't underflow
        uint256 permit2Nonce = 0;
        uint256 betAmount = 100 * 10 ** 18;

        Floor.CreateGameParams memory params = Floor.CreateGameParams({
            nonce: nonce,
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
            ISignatureTransfer.SignatureTransferDetails({to: address(floor), requestedAmount: betAmount});

        bytes memory permitSignature =
            createPermit2Signature(address(token), betAmount, permit2Nonce, deadline, address(floor));

        vm.prank(player);
        vm.expectRevert(Floor.SignatureExpired.selector);
        floor.createGameWithPermit2(params, signature, permit, transferDetails, permitSignature);
    }

    function testCreateGameWithPermit2NonceReuse() public {
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 permit2Nonce = 0;
        uint256 betAmount = 100 * 10 ** 18;

        Floor.CreateGameParams memory params = Floor.CreateGameParams({
            nonce: nonce,
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
            ISignatureTransfer.SignatureTransferDetails({to: address(floor), requestedAmount: betAmount});

        bytes memory permitSignature =
            createPermit2Signature(address(token), betAmount, permit2Nonce, deadline, address(floor));

        // First call should succeed
        vm.prank(player);
        floor.createGameWithPermit2(params, signature, permit, transferDetails, permitSignature);

        // Second call with same nonce should fail
        vm.prank(player);
        vm.expectRevert(abi.encodeWithSelector(Floor.NonceAlreadyUsed.selector, nonce));
        floor.createGameWithPermit2(params, signature, permit, transferDetails, permitSignature);
    }

    function testCreateGameWithPermit2InvalidTransferDestination() public {
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 permit2Nonce = 0;
        uint256 betAmount = 100 * 10 ** 18;

        Floor.CreateGameParams memory params = Floor.CreateGameParams({
            nonce: nonce,
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
        vm.expectRevert(Floor.InvalidPermitTransfer.selector);
        floor.createGameWithPermit2(params, signature, permit, transferDetails, permitSignature);
    }

    function testCreateGameWithPermit2InvalidRequestedAmount() public {
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 permit2Nonce = 0;
        uint256 betAmount = 100 * 10 ** 18;
        uint256 wrongAmount = 50 * 10 ** 18; // Different from bet amount

        Floor.CreateGameParams memory params = Floor.CreateGameParams({
            nonce: nonce,
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
            to: address(floor),
            requestedAmount: wrongAmount // Different from bet amount
        });

        bytes memory permitSignature =
            createPermit2Signature(address(token), betAmount, permit2Nonce, deadline, address(floor));

        vm.prank(player);
        vm.expectRevert(abi.encodeWithSelector(Floor.InvalidAmount.selector, wrongAmount));
        floor.createGameWithPermit2(params, signature, permit, transferDetails, permitSignature);
    }
}
