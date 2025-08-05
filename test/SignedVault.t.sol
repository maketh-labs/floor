// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {SignedVault} from "../src/SignedVault.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {ISignatureTransfer} from "permit2/src/interfaces/ISignatureTransfer.sol";
import {DeployPermit2} from "permit2/test/utils/DeployPermit2.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract SignedVaultTest is Test, DeployPermit2 {
    SignedVault public signedVault;
    ERC20Mock public token;
    ISignatureTransfer public permit2;

    // Test accounts
    address public user;
    address public resolver1;
    address public resolver2;
    address public owner;

    // Private keys for signing
    uint256 public userPrivateKey;
    uint256 public resolver1PrivateKey;
    uint256 public resolver2PrivateKey;
    uint256 public ownerPrivateKey;

    // Test constants
    uint256 public constant DEPOSIT_AMOUNT = 1 ether;
    uint256 public constant TOKEN_DEPOSIT_AMOUNT = 1000 * 10 ** 18;

    // EIP712 domain separator for testing
    bytes32 public domainSeparator;
    bytes32 public permit2DomainSeparator;

    // Type hashes
    bytes32 public constant WITHDRAW_TYPEHASH =
        keccak256("Withdraw(address user,address token,uint256 amount,address resolver,uint256 nonce,uint256 deadline)");

    bytes32 public constant PERMIT_TRANSFER_FROM_TYPEHASH = keccak256(
        "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
    );

    // Events to test
    event Deposit(address user, address token, uint256 amount, uint256 nonce);
    event NonceCancelled(address resolver, uint256 nonce);
    event Withdraw(address user, address token, uint256 amount);

    // Helper function to create a basic ETH deposit
    function createBasicETHDeposit(address depositor, address resolverAddr, uint256 amount, uint256 nonce) internal {
        vm.prank(depositor);
        signedVault.depositETH{value: amount}(resolverAddr, nonce);
    }

    // Helper function to create a basic token deposit
    function createBasicTokenDeposit(address depositor, address resolverAddr, uint256 amount, uint256 nonce) internal {
        vm.prank(depositor);
        token.approve(address(signedVault), amount);
        vm.prank(depositor);
        signedVault.deposit(address(token), amount, resolverAddr, nonce);
    }

    // Helper function to calculate deposit hash
    function calculateDepositHash(address userAddr, address tokenAddr, address resolverAddr, uint256 nonce)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(userAddr, tokenAddr, resolverAddr, nonce));
    }

    function setUp() public {
        // Deploy actual Permit2 contract
        permit2 = ISignatureTransfer(deployPermit2());

        // Set up test accounts
        (user, userPrivateKey) = makeAddrAndKey("user");
        (resolver1, resolver1PrivateKey) = makeAddrAndKey("resolver1");
        (resolver2, resolver2PrivateKey) = makeAddrAndKey("resolver2");
        (owner, ownerPrivateKey) = makeAddrAndKey("owner");

        // Deploy SignedVault implementation
        SignedVault implementation = new SignedVault(address(permit2));

        // Deploy proxy with initialization
        bytes memory initData = abi.encodeWithSelector(
            SignedVault.initialize.selector,
            owner // owner
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        signedVault = SignedVault(payable(address(proxy)));
        token = new ERC20Mock();

        // Fund test accounts
        vm.deal(user, 10 ether);
        token.mint(user, 10000 * 10 ** 18);

        // Approve Permit2 to spend tokens
        vm.prank(user);
        token.approve(address(permit2), type(uint256).max);

        // Compute domain separators
        domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("SignedVault"),
                keccak256("1"),
                block.chainid,
                address(signedVault)
            )
        );

        // Get actual Permit2 domain separator
        permit2DomainSeparator = permit2.DOMAIN_SEPARATOR();
    }

    // Helper function to create withdrawal signatures
    function createWithdrawSignature(
        address userAddr,
        address tokenAddr,
        uint256 amount,
        address resolver,
        uint256 resolverPrivateKey,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(abi.encode(WITHDRAW_TYPEHASH, userAddr, tokenAddr, amount, resolver, nonce, deadline))
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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, messageHash);
        return abi.encodePacked(r, s, v);
    }

    // ============ CONSTRUCTOR TESTS ============

    function testConstructor() public view {
        assertEq(signedVault.owner(), owner);
        assertEq(address(signedVault.PERMIT2()), address(permit2));
        assertEq(signedVault.ETH_ADDRESS(), address(0));
    }

    // ============ DEPOSIT TESTS ============

    function testDepositETH() public {
        uint256 nonce = 1;

        // Expect the Deposit event with nonce
        vm.expectEmit(true, true, true, true);
        emit Deposit(user, signedVault.ETH_ADDRESS(), DEPOSIT_AMOUNT, nonce);

        vm.prank(user);
        signedVault.depositETH{value: DEPOSIT_AMOUNT}(resolver1, nonce);

        // Contract should receive the ETH
        assertEq(address(signedVault).balance, DEPOSIT_AMOUNT);
        // Resolver1 should be credited with the deposit
        assertEq(signedVault.resolverBalanceOf(resolver1, signedVault.ETH_ADDRESS()), DEPOSIT_AMOUNT);

        // Check deposit verification storage
        bytes32 depositHash = calculateDepositHash(user, signedVault.ETH_ADDRESS(), resolver1, nonce);
        assertEq(signedVault.getDeposit(depositHash), DEPOSIT_AMOUNT);
    }

    function testDepositETHInvalidResolver() public {
        uint256 nonce = 1;
        vm.prank(user);
        vm.expectRevert(SignedVault.InvalidResolver.selector);
        signedVault.depositETH{value: DEPOSIT_AMOUNT}(address(0), nonce);
    }

    function testDepositETHDuplicate() public {
        uint256 nonce = 1;

        // First deposit should succeed
        vm.prank(user);
        signedVault.depositETH{value: DEPOSIT_AMOUNT}(resolver1, nonce);

        // Second deposit with same nonce should fail
        bytes32 expectedHash = calculateDepositHash(user, signedVault.ETH_ADDRESS(), resolver1, nonce);
        vm.expectRevert(abi.encodeWithSelector(SignedVault.DuplicateDeposit.selector, expectedHash));
        vm.prank(user);
        signedVault.depositETH{value: DEPOSIT_AMOUNT}(resolver1, nonce);
    }

    function testDepositERC20() public {
        uint256 nonce = 1;

        vm.prank(user);
        token.approve(address(signedVault), TOKEN_DEPOSIT_AMOUNT);

        // Expect the Deposit event with nonce
        vm.expectEmit(true, true, true, true);
        emit Deposit(user, address(token), TOKEN_DEPOSIT_AMOUNT, nonce);

        vm.prank(user);
        signedVault.deposit(address(token), TOKEN_DEPOSIT_AMOUNT, resolver1, nonce);

        // Contract should receive the tokens
        assertEq(token.balanceOf(address(signedVault)), TOKEN_DEPOSIT_AMOUNT);
        // Resolver1 should be credited with the deposit
        assertEq(signedVault.resolverBalanceOf(resolver1, address(token)), TOKEN_DEPOSIT_AMOUNT);

        // Check deposit verification storage
        bytes32 depositHash = calculateDepositHash(user, address(token), resolver1, nonce);
        assertEq(signedVault.getDeposit(depositHash), TOKEN_DEPOSIT_AMOUNT);
    }

    function testDepositERC20InvalidAsset() public {
        uint256 nonce = 1;
        vm.prank(user);
        vm.expectRevert(SignedVault.InvalidAsset.selector);
        signedVault.deposit(address(0), TOKEN_DEPOSIT_AMOUNT, resolver1, nonce);
    }

    function testDepositERC20InvalidResolver() public {
        uint256 nonce = 1;
        vm.prank(user);
        vm.expectRevert(SignedVault.InvalidResolver.selector);
        signedVault.deposit(address(token), TOKEN_DEPOSIT_AMOUNT, address(0), nonce);
    }

    function testDepositERC20Duplicate() public {
        uint256 nonce = 1;

        // First deposit should succeed
        vm.prank(user);
        token.approve(address(signedVault), TOKEN_DEPOSIT_AMOUNT * 2);
        vm.prank(user);
        signedVault.deposit(address(token), TOKEN_DEPOSIT_AMOUNT, resolver1, nonce);

        // Second deposit with same nonce should fail
        bytes32 expectedHash = calculateDepositHash(user, address(token), resolver1, nonce);
        vm.expectRevert(abi.encodeWithSelector(SignedVault.DuplicateDeposit.selector, expectedHash));
        vm.prank(user);
        signedVault.deposit(address(token), TOKEN_DEPOSIT_AMOUNT, resolver1, nonce);
    }

    // ============ PERMIT2 DEPOSIT TESTS ============

    function testDepositWithPermit2() public {
        uint256 nonce = 0;
        uint256 userNonce = 1; // User's deposit nonce
        uint256 deadline = block.timestamp + 1 hours;
        uint256 amount = TOKEN_DEPOSIT_AMOUNT;

        // Create Permit2 permit
        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({token: address(token), amount: amount}),
            nonce: nonce,
            deadline: deadline
        });

        bytes memory permitSignature =
            createPermit2Signature(address(token), amount, nonce, deadline, address(signedVault));

        // Expect the Deposit event with nonce
        vm.expectEmit(true, true, true, true);
        emit Deposit(user, address(token), amount, userNonce);

        vm.prank(user);
        signedVault.depositWithPermit2(resolver1, permit, permitSignature, userNonce);

        // Contract should receive the tokens
        assertEq(token.balanceOf(address(signedVault)), amount);
        // Resolver1 should be credited with the deposit
        assertEq(signedVault.resolverBalanceOf(resolver1, address(token)), amount);

        // Check deposit verification storage
        bytes32 depositHash = calculateDepositHash(user, address(token), resolver1, userNonce);
        assertEq(signedVault.getDeposit(depositHash), amount);
    }

    function testDepositWithPermit2InvalidAsset() public {
        uint256 nonce = 0;
        uint256 userNonce = 1;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 amount = TOKEN_DEPOSIT_AMOUNT;

        // Create permit for ETH address (invalid)
        ISignatureTransfer.PermitTransferFrom memory invalidPermit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({token: address(0), amount: amount}),
            nonce: nonce,
            deadline: deadline
        });

        bytes memory invalidPermitSignature =
            createPermit2Signature(address(0), amount, nonce, deadline, address(signedVault));

        vm.prank(user);
        vm.expectRevert(SignedVault.InvalidAsset.selector);
        signedVault.depositWithPermit2(resolver1, invalidPermit, invalidPermitSignature, userNonce);
    }

    function testDepositWithPermit2Duplicate() public {
        uint256 nonce1 = 0;
        uint256 nonce2 = 1;
        uint256 userNonce = 1; // Same user nonce for both deposits
        uint256 deadline = block.timestamp + 1 hours;
        uint256 amount = TOKEN_DEPOSIT_AMOUNT / 2;

        // First deposit should succeed
        ISignatureTransfer.PermitTransferFrom memory permit1 = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({token: address(token), amount: amount}),
            nonce: nonce1,
            deadline: deadline
        });

        bytes memory permitSignature1 =
            createPermit2Signature(address(token), amount, nonce1, deadline, address(signedVault));

        vm.prank(user);
        signedVault.depositWithPermit2(resolver1, permit1, permitSignature1, userNonce);

        // Second deposit with same user nonce should fail
        ISignatureTransfer.PermitTransferFrom memory permitSecond = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({token: address(token), amount: amount}),
            nonce: nonce2,
            deadline: deadline
        });

        bytes memory permitSignature2 =
            createPermit2Signature(address(token), amount, nonce2, deadline, address(signedVault));

        bytes32 expectedHash = calculateDepositHash(user, address(token), resolver1, userNonce);
        vm.expectRevert(abi.encodeWithSelector(SignedVault.DuplicateDeposit.selector, expectedHash));
        vm.prank(user);
        signedVault.depositWithPermit2(resolver1, permitSecond, permitSignature2, userNonce);
    }

    // ============ WITHDRAWAL TESTS ============

    function testWithdrawETH() public {
        // First deposit
        createBasicETHDeposit(user, resolver1, DEPOSIT_AMOUNT, 1);

        uint256 withdrawAmount = DEPOSIT_AMOUNT / 2;
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 1 hours;

        bytes memory signature =
            createWithdrawSignature(user, address(0), withdrawAmount, resolver1, resolver1PrivateKey, nonce, deadline);

        uint256 balanceBefore = user.balance;

        // Expect the Withdraw event
        vm.expectEmit(true, true, true, true);
        emit Withdraw(user, address(0), withdrawAmount);

        vm.prank(user);
        signedVault.withdrawETH(user, withdrawAmount, resolver1, nonce, deadline, signature);

        assertEq(user.balance, balanceBefore + withdrawAmount);
        assertEq(signedVault.resolverBalanceOf(resolver1, address(0)), DEPOSIT_AMOUNT - withdrawAmount);
        assertTrue(signedVault.usedNonces(resolver1, nonce));
    }

    function testWithdrawERC20() public {
        // First deposit
        createBasicTokenDeposit(user, resolver1, TOKEN_DEPOSIT_AMOUNT, 1);

        uint256 withdrawAmount = TOKEN_DEPOSIT_AMOUNT / 2;
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 1 hours;

        bytes memory signature = createWithdrawSignature(
            user, address(token), withdrawAmount, resolver1, resolver1PrivateKey, nonce, deadline
        );

        uint256 balanceBefore = token.balanceOf(user);

        // Expect the Withdraw event
        vm.expectEmit(true, true, true, true);
        emit Withdraw(user, address(token), withdrawAmount);

        vm.prank(user);
        signedVault.withdraw(user, address(token), withdrawAmount, resolver1, nonce, deadline, signature);

        assertEq(token.balanceOf(user), balanceBefore + withdrawAmount);
        assertEq(signedVault.resolverBalanceOf(resolver1, address(token)), TOKEN_DEPOSIT_AMOUNT - withdrawAmount);
        assertTrue(signedVault.usedNonces(resolver1, nonce));
    }

    function testWithdrawInsufficientResolverBalance() public {
        // Resolver has no balance, should fail
        uint256 withdrawAmount = DEPOSIT_AMOUNT;
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 1 hours;

        bytes memory signature =
            createWithdrawSignature(user, address(0), withdrawAmount, resolver1, resolver1PrivateKey, nonce, deadline);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                SignedVault.InsufficientResolverBalance.selector, resolver1, address(0), withdrawAmount, 0
            )
        );
        signedVault.withdrawETH(user, withdrawAmount, resolver1, nonce, deadline, signature);
    }

    function testWithdrawExpiredSignature() public {
        uint256 nonce = 1;
        vm.prank(user);
        signedVault.depositETH{value: DEPOSIT_AMOUNT}(resolver1, nonce);

        uint256 withdrawAmount = DEPOSIT_AMOUNT / 2;
        uint256 withdrawNonce = 1;
        uint256 deadline = block.timestamp - 1; // Expired

        bytes memory signature = createWithdrawSignature(
            user, address(0), withdrawAmount, resolver1, resolver1PrivateKey, withdrawNonce, deadline
        );

        vm.prank(user);
        vm.expectRevert(SignedVault.SignatureExpired.selector);
        signedVault.withdrawETH(user, withdrawAmount, resolver1, withdrawNonce, deadline, signature);
    }

    function testWithdrawNonceReuse() public {
        uint256 nonce = 1;
        vm.prank(user);
        signedVault.depositETH{value: DEPOSIT_AMOUNT}(resolver1, nonce);

        uint256 withdrawAmount = DEPOSIT_AMOUNT / 4;
        uint256 withdrawNonce = 1;
        uint256 deadline = block.timestamp + 1 hours;

        bytes memory signature = createWithdrawSignature(
            user, address(0), withdrawAmount, resolver1, resolver1PrivateKey, withdrawNonce, deadline
        );

        // First withdrawal should succeed
        vm.prank(user);
        signedVault.withdrawETH(user, withdrawAmount, resolver1, withdrawNonce, deadline, signature);

        // Second withdrawal with same nonce should fail
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(SignedVault.NonceAlreadyUsed.selector, resolver1, withdrawNonce));
        signedVault.withdrawETH(user, withdrawAmount, resolver1, withdrawNonce, deadline, signature);
    }

    function testWithdrawInvalidSignature() public {
        createBasicETHDeposit(user, resolver1, DEPOSIT_AMOUNT, 1);

        uint256 withdrawAmount = DEPOSIT_AMOUNT / 2;
        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 1 hours;

        // Create signature with wrong private key (using resolver2's key instead of resolver1's)
        bytes memory wrongSignature =
            createWithdrawSignature(user, address(0), withdrawAmount, resolver1, resolver2PrivateKey, nonce, deadline);

        vm.prank(user);
        vm.expectRevert(SignedVault.InvalidSignature.selector);
        signedVault.withdrawETH(user, withdrawAmount, resolver1, nonce, deadline, wrongSignature);
    }

    function testWithdrawZeroAmount() public {
        createBasicETHDeposit(user, resolver1, DEPOSIT_AMOUNT, 1);

        uint256 nonce = 1;
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature =
            createWithdrawSignature(user, address(0), 0, resolver1, resolver1PrivateKey, nonce, deadline);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(SignedVault.InvalidAmount.selector, 0));
        signedVault.withdrawETH(user, 0, resolver1, nonce, deadline, signature);
    }

    // ============ RESOLVER TESTS ============

    function testMultipleResolvers() public {
        // Deposit with different resolvers
        uint256 nonce1 = 1;
        uint256 nonce2 = 2;

        vm.prank(user);
        signedVault.depositETH{value: DEPOSIT_AMOUNT}(resolver1, nonce1);

        vm.prank(user);
        token.approve(address(signedVault), TOKEN_DEPOSIT_AMOUNT);
        vm.prank(user);
        signedVault.deposit(address(token), TOKEN_DEPOSIT_AMOUNT, resolver2, nonce2);

        // Check balances
        assertEq(signedVault.resolverBalanceOf(resolver1, address(0)), DEPOSIT_AMOUNT);
        assertEq(signedVault.resolverBalanceOf(resolver2, address(token)), TOKEN_DEPOSIT_AMOUNT);
        assertEq(signedVault.resolverBalanceOf(resolver1, address(token)), 0);
        assertEq(signedVault.resolverBalanceOf(resolver2, address(0)), 0);
    }

    // ============ VIEW FUNCTION TESTS ============

    function testGetDepositByHash() public {
        uint256 nonce = 1;
        createBasicETHDeposit(user, resolver1, DEPOSIT_AMOUNT, nonce);

        bytes32 depositHash = calculateDepositHash(user, signedVault.ETH_ADDRESS(), resolver1, nonce);

        // Test getDeposit with hash
        assertEq(signedVault.getDeposit(depositHash), DEPOSIT_AMOUNT);

        // Test getDeposit with parameters
        assertEq(signedVault.getDeposit(user, signedVault.ETH_ADDRESS(), resolver1, nonce), DEPOSIT_AMOUNT);
    }

    function testGetDepositByParameters() public {
        uint256 nonce = 1;
        createBasicTokenDeposit(user, resolver1, TOKEN_DEPOSIT_AMOUNT, nonce);

        // Test getDeposit with parameters
        assertEq(signedVault.getDeposit(user, address(token), resolver1, nonce), TOKEN_DEPOSIT_AMOUNT);

        // Test getDeposit with hash
        bytes32 depositHash = calculateDepositHash(user, address(token), resolver1, nonce);
        assertEq(signedVault.getDeposit(depositHash), TOKEN_DEPOSIT_AMOUNT);
    }

    function testGetDepositNonExistent() public view {
        uint256 nonce = 999;

        // Test non-existent deposit with hash
        bytes32 nonExistentHash = calculateDepositHash(user, signedVault.ETH_ADDRESS(), resolver1, nonce);
        assertEq(signedVault.getDeposit(nonExistentHash), 0);

        // Test non-existent deposit with parameters
        assertEq(signedVault.getDeposit(user, signedVault.ETH_ADDRESS(), resolver1, nonce), 0);
    }

    function testGetResolverBalance() public {
        uint256 nonce1 = 1;
        uint256 nonce2 = 2;

        vm.prank(user);
        signedVault.depositETH{value: DEPOSIT_AMOUNT}(resolver1, nonce1);

        vm.prank(user);
        token.approve(address(signedVault), TOKEN_DEPOSIT_AMOUNT);
        vm.prank(user);
        signedVault.deposit(address(token), TOKEN_DEPOSIT_AMOUNT, resolver2, nonce2);

        // Test resolver balance queries
        assertEq(signedVault.resolverBalanceOf(resolver1, address(0)), DEPOSIT_AMOUNT);
        assertEq(signedVault.resolverBalanceOf(resolver2, address(token)), TOKEN_DEPOSIT_AMOUNT);
        assertEq(signedVault.resolverBalanceOf(resolver1, address(token)), 0);
        assertEq(signedVault.resolverBalanceOf(resolver2, address(0)), 0);
    }

    // ============ DEPOSIT TESTS ============

    function testDepositIndependenceAcrossUsers() public {
        uint256 nonce = 1;

        // User deposits with nonce 1
        createBasicETHDeposit(user, resolver1, DEPOSIT_AMOUNT, nonce);

        // Resolver1 can still use the same nonce for their own deposit
        vm.deal(resolver1, DEPOSIT_AMOUNT);
        createBasicETHDeposit(resolver1, resolver2, DEPOSIT_AMOUNT, nonce);

        // Both deposits should be successful and tracked separately
        bytes32 userDepositHash = calculateDepositHash(user, signedVault.ETH_ADDRESS(), resolver1, nonce);
        bytes32 resolver1DepositHash = calculateDepositHash(resolver1, signedVault.ETH_ADDRESS(), resolver2, nonce);
        assertEq(signedVault.getDeposit(userDepositHash), DEPOSIT_AMOUNT);
        assertEq(signedVault.getDeposit(resolver1DepositHash), DEPOSIT_AMOUNT);
    }

    function testMultipleDepositsWithDifferentNonces() public {
        uint256 nonce1 = 1;
        uint256 nonce2 = 2;
        uint256 amount1 = DEPOSIT_AMOUNT;
        uint256 amount2 = DEPOSIT_AMOUNT * 2;

        // Make two different deposits with different nonces
        createBasicETHDeposit(user, resolver1, amount1, nonce1);
        createBasicETHDeposit(user, resolver1, amount2, nonce2);

        // Both should be tracked independently
        bytes32 depositHash1 = calculateDepositHash(user, signedVault.ETH_ADDRESS(), resolver1, nonce1);
        bytes32 depositHash2 = calculateDepositHash(user, signedVault.ETH_ADDRESS(), resolver1, nonce2);
        assertEq(signedVault.getDeposit(depositHash1), amount1);
        assertEq(signedVault.getDeposit(depositHash2), amount2);

        // Resolver balance should be the sum
        assertEq(signedVault.resolverBalanceOf(resolver1, signedVault.ETH_ADDRESS()), amount1 + amount2);
    }

    function testMixedTokenDepositsWithDifferentNonces() public {
        uint256 ethNonce = 1;
        uint256 tokenNonce = 2;

        // ETH deposit
        createBasicETHDeposit(user, resolver1, DEPOSIT_AMOUNT, ethNonce);

        // Token deposit
        createBasicTokenDeposit(user, resolver1, TOKEN_DEPOSIT_AMOUNT, tokenNonce);

        // Both should be tracked independently
        bytes32 ethDepositHash = calculateDepositHash(user, signedVault.ETH_ADDRESS(), resolver1, ethNonce);
        bytes32 tokenDepositHash = calculateDepositHash(user, address(token), resolver1, tokenNonce);
        assertEq(signedVault.getDeposit(ethDepositHash), DEPOSIT_AMOUNT);
        assertEq(signedVault.getDeposit(tokenDepositHash), TOKEN_DEPOSIT_AMOUNT);
    }

    function testFlexibleNonceUsage() public {
        // Test that our flexible helper functions enable various nonce scenarios

        // Fund resolver1 for the test
        vm.deal(resolver1, DEPOSIT_AMOUNT);

        // Different users, same nonce - should work
        createBasicETHDeposit(user, resolver1, DEPOSIT_AMOUNT, 42);
        createBasicETHDeposit(resolver1, resolver2, DEPOSIT_AMOUNT / 2, 42);

        // Same user, different nonces - should work
        createBasicETHDeposit(user, resolver1, DEPOSIT_AMOUNT / 4, 100);
        createBasicETHDeposit(user, resolver1, DEPOSIT_AMOUNT / 4, 200);

        // Verify all deposits were recorded correctly
        bytes32 userHash42 = calculateDepositHash(user, signedVault.ETH_ADDRESS(), resolver1, 42);
        bytes32 resolver1Hash42 = calculateDepositHash(resolver1, signedVault.ETH_ADDRESS(), resolver2, 42);
        bytes32 userHash100 = calculateDepositHash(user, signedVault.ETH_ADDRESS(), resolver1, 100);
        bytes32 userHash200 = calculateDepositHash(user, signedVault.ETH_ADDRESS(), resolver1, 200);

        assertEq(signedVault.getDeposit(userHash42), DEPOSIT_AMOUNT);
        assertEq(signedVault.getDeposit(resolver1Hash42), DEPOSIT_AMOUNT / 2);
        assertEq(signedVault.getDeposit(userHash100), DEPOSIT_AMOUNT / 4);
        assertEq(signedVault.getDeposit(userHash200), DEPOSIT_AMOUNT / 4);

        // Test duplicate nonce should fail
        bytes32 expectedDuplicateHash = calculateDepositHash(user, signedVault.ETH_ADDRESS(), resolver1, 42);
        vm.expectRevert(abi.encodeWithSelector(SignedVault.DuplicateDeposit.selector, expectedDuplicateHash));
        createBasicETHDeposit(user, resolver1, DEPOSIT_AMOUNT, 42);
    }

    // ============ NONCE CANCELLATION TESTS ============

    function testCancelNonce() public {
        uint256 nonce = 1;

        // Expect the NonceCancelled event
        vm.expectEmit(true, true, true, true);
        emit NonceCancelled(resolver1, nonce);

        // Resolver cancels the nonce
        vm.prank(resolver1);
        signedVault.cancel(nonce);

        // Check that nonce is marked as used (cancelled)
        assertTrue(signedVault.usedNonces(resolver1, nonce));
    }

    function testCancelledNoncePreventsWithdrawal() public {
        uint256 nonce = 1;
        vm.prank(user);
        signedVault.depositETH{value: DEPOSIT_AMOUNT}(resolver1, nonce);

        uint256 withdrawAmount = DEPOSIT_AMOUNT / 2;
        uint256 withdrawNonce = 1;
        uint256 deadline = block.timestamp + 1 hours;

        // Resolver cancels the nonce first
        vm.prank(resolver1);
        signedVault.cancel(withdrawNonce);

        // Create signature for withdrawal
        bytes memory signature = createWithdrawSignature(
            user, address(0), withdrawAmount, resolver1, resolver1PrivateKey, withdrawNonce, deadline
        );

        // Withdrawal should fail with NonceAlreadyUsed error
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(SignedVault.NonceAlreadyUsed.selector, resolver1, withdrawNonce));
        signedVault.withdrawETH(user, withdrawAmount, resolver1, withdrawNonce, deadline, signature);
    }

    function testCancelNonceAfterUse() public {
        uint256 nonce = 1;
        vm.prank(user);
        signedVault.depositETH{value: DEPOSIT_AMOUNT}(resolver1, nonce);

        uint256 withdrawAmount = DEPOSIT_AMOUNT / 2;
        uint256 withdrawNonce = 1;
        uint256 deadline = block.timestamp + 1 hours;

        // Create and use signature first
        bytes memory signature = createWithdrawSignature(
            user, address(0), withdrawAmount, resolver1, resolver1PrivateKey, withdrawNonce, deadline
        );

        vm.prank(user);
        signedVault.withdrawETH(user, withdrawAmount, resolver1, withdrawNonce, deadline, signature);

        // Nonce should already be marked as used
        assertTrue(signedVault.usedNonces(resolver1, withdrawNonce));

        // Now try to cancel the already-used nonce (should revert with NonceAlreadyUsed)
        vm.prank(resolver1);
        vm.expectRevert(abi.encodeWithSelector(SignedVault.NonceAlreadyUsed.selector, resolver1, withdrawNonce));
        signedVault.cancel(withdrawNonce);

        // Nonce should still be marked as used
        assertTrue(signedVault.usedNonces(resolver1, withdrawNonce));
    }

    function testMultipleResolversIndependentNonces() public {
        uint256 nonce1 = 1;
        uint256 nonce2 = 2; // Different nonce values

        // Resolver1 cancels their nonce1
        vm.prank(resolver1);
        signedVault.cancel(nonce1);

        // Resolver2 cancels their nonce2
        vm.prank(resolver2);
        signedVault.cancel(nonce2);

        // Both nonces should be marked as used for their respective resolvers
        assertTrue(signedVault.usedNonces(resolver1, nonce1));
        assertTrue(signedVault.usedNonces(resolver2, nonce2));

        // But resolver1's nonce2 should still be unused, and resolver2's nonce1 should still be unused
        assertFalse(signedVault.usedNonces(resolver1, nonce2));
        assertFalse(signedVault.usedNonces(resolver2, nonce1));
    }
}
