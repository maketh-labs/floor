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
        keccak256("Withdraw(address user,address token,uint256 amount,address resolver,uint256 deadline)");

    bytes32 public constant PERMIT_TRANSFER_FROM_TYPEHASH = keccak256(
        "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
    );

    function setUp() public {
        // Deploy actual Permit2 contract
        permit2 = ISignatureTransfer(deployPermit2());

        // Set up test accounts
        (user, userPrivateKey) = makeAddrAndKey("user");
        (resolver1, resolver1PrivateKey) = makeAddrAndKey("resolver1");
        (resolver2, resolver2PrivateKey) = makeAddrAndKey("resolver2");
        (owner, ownerPrivateKey) = makeAddrAndKey("owner");

        // Deploy Tapital implementation
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
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(abi.encode(WITHDRAW_TYPEHASH, userAddr, tokenAddr, amount, resolver, deadline))
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
        vm.prank(user);
        signedVault.depositETH{value: DEPOSIT_AMOUNT}(resolver1);

        // Contract should receive the ETH
        assertEq(address(signedVault).balance, DEPOSIT_AMOUNT);
        // Resolver1 should be credited with the deposit
        assertEq(signedVault.resolverBalanceOf(resolver1, signedVault.ETH_ADDRESS()), DEPOSIT_AMOUNT);
    }

    function testDepositETHInvalidResolver() public {
        vm.prank(user);
        vm.expectRevert(SignedVault.InvalidResolver.selector);
        signedVault.depositETH{value: DEPOSIT_AMOUNT}(address(0));
    }

    function testDepositERC20() public {
        vm.prank(user);
        token.approve(address(signedVault), TOKEN_DEPOSIT_AMOUNT);

        vm.prank(user);
        signedVault.deposit(address(token), TOKEN_DEPOSIT_AMOUNT, resolver1);

        // Contract should receive the tokens
        assertEq(token.balanceOf(address(signedVault)), TOKEN_DEPOSIT_AMOUNT);
        // Resolver1 should be credited with the deposit
        assertEq(signedVault.resolverBalanceOf(resolver1, address(token)), TOKEN_DEPOSIT_AMOUNT);
    }

    function testDepositERC20InvalidAsset() public {
        vm.prank(user);
        vm.expectRevert(SignedVault.InvalidAsset.selector);
        signedVault.deposit(address(0), TOKEN_DEPOSIT_AMOUNT, resolver1);
    }

    function testDepositERC20InvalidResolver() public {
        vm.prank(user);
        vm.expectRevert(SignedVault.InvalidResolver.selector);
        signedVault.deposit(address(token), TOKEN_DEPOSIT_AMOUNT, address(0));
    }

    // ============ PERMIT2 DEPOSIT TESTS ============

    function testDepositWithPermit2() public {
        uint256 nonce = 0;
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

        vm.prank(user);
        signedVault.depositWithPermit2(resolver1, permit, permitSignature);

        // Contract should receive the tokens
        assertEq(token.balanceOf(address(signedVault)), amount);
        // Resolver1 should be credited with the deposit
        assertEq(signedVault.resolverBalanceOf(resolver1, address(token)), amount);
    }

    function testDepositWithPermit2InvalidAsset() public {
        uint256 nonce = 0;
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
        signedVault.depositWithPermit2(resolver1, invalidPermit, invalidPermitSignature);
    }

    // ============ WITHDRAWAL TESTS ============

    function testWithdrawETH() public {
        // First deposit
        vm.prank(user);
        signedVault.depositETH{value: DEPOSIT_AMOUNT}(resolver1);

        uint256 withdrawAmount = DEPOSIT_AMOUNT / 2;
        uint256 deadline = block.timestamp + 1 hours;

        bytes memory signature =
            createWithdrawSignature(user, address(0), withdrawAmount, resolver1, resolver1PrivateKey, deadline);

        uint256 balanceBefore = user.balance;

        vm.prank(user);
        signedVault.withdrawETH(user, withdrawAmount, resolver1, deadline, signature);

        assertEq(user.balance, balanceBefore + withdrawAmount);
        assertEq(signedVault.resolverBalanceOf(resolver1, address(0)), DEPOSIT_AMOUNT - withdrawAmount);
        assertTrue(signedVault.usedSignatures(keccak256(signature)));
    }

    function testWithdrawERC20() public {
        // First deposit
        vm.prank(user);
        token.approve(address(signedVault), TOKEN_DEPOSIT_AMOUNT);
        vm.prank(user);
        signedVault.deposit(address(token), TOKEN_DEPOSIT_AMOUNT, resolver1);

        uint256 withdrawAmount = TOKEN_DEPOSIT_AMOUNT / 2;
        uint256 deadline = block.timestamp + 1 hours;

        bytes memory signature =
            createWithdrawSignature(user, address(token), withdrawAmount, resolver1, resolver1PrivateKey, deadline);

        uint256 balanceBefore = token.balanceOf(user);

        vm.prank(user);
        signedVault.withdraw(user, address(token), withdrawAmount, resolver1, deadline, signature);

        assertEq(token.balanceOf(user), balanceBefore + withdrawAmount);
        assertEq(signedVault.resolverBalanceOf(resolver1, address(token)), TOKEN_DEPOSIT_AMOUNT - withdrawAmount);
        assertTrue(signedVault.usedSignatures(keccak256(signature)));
    }

    function testWithdrawInsufficientResolverBalance() public {
        // Resolver has no balance, should fail
        uint256 withdrawAmount = DEPOSIT_AMOUNT;
        uint256 deadline = block.timestamp + 1 hours;

        bytes memory signature =
            createWithdrawSignature(user, address(0), withdrawAmount, resolver1, resolver1PrivateKey, deadline);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                SignedVault.InsufficientResolverBalance.selector, resolver1, address(0), withdrawAmount, 0
            )
        );
        signedVault.withdrawETH(user, withdrawAmount, resolver1, deadline, signature);
    }

    function testWithdrawExpiredSignature() public {
        vm.prank(user);
        signedVault.depositETH{value: DEPOSIT_AMOUNT}(resolver1);

        uint256 withdrawAmount = DEPOSIT_AMOUNT / 2;
        uint256 deadline = block.timestamp - 1; // Expired

        bytes memory signature =
            createWithdrawSignature(user, address(0), withdrawAmount, resolver1, resolver1PrivateKey, deadline);

        vm.prank(user);
        vm.expectRevert(SignedVault.SignatureExpired.selector);
        signedVault.withdrawETH(user, withdrawAmount, resolver1, deadline, signature);
    }

    function testWithdrawSignatureReuse() public {
        vm.prank(user);
        signedVault.depositETH{value: DEPOSIT_AMOUNT}(resolver1);

        uint256 withdrawAmount = DEPOSIT_AMOUNT / 4;
        uint256 deadline = block.timestamp + 1 hours;

        bytes memory signature =
            createWithdrawSignature(user, address(0), withdrawAmount, resolver1, resolver1PrivateKey, deadline);

        // First withdrawal should succeed
        vm.prank(user);
        signedVault.withdrawETH(user, withdrawAmount, resolver1, deadline, signature);

        // Second withdrawal with same signature should fail
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(SignedVault.SignatureAlreadyUsed.selector, keccak256(signature)));
        signedVault.withdrawETH(user, withdrawAmount, resolver1, deadline, signature);
    }

    function testWithdrawInvalidSignature() public {
        vm.prank(user);
        signedVault.depositETH{value: DEPOSIT_AMOUNT}(resolver1);

        uint256 withdrawAmount = DEPOSIT_AMOUNT / 2;
        uint256 deadline = block.timestamp + 1 hours;

        // Create signature with wrong private key (using resolver2's key instead of resolver1's)
        bytes memory wrongSignature =
            createWithdrawSignature(user, address(0), withdrawAmount, resolver1, resolver2PrivateKey, deadline);

        vm.prank(user);
        vm.expectRevert(SignedVault.InvalidSignature.selector);
        signedVault.withdrawETH(user, withdrawAmount, resolver1, deadline, wrongSignature);
    }

    // ============ RESOLVER TESTS ============

    function testMultipleResolvers() public {
        // Deposit with different resolvers
        vm.prank(user);
        signedVault.depositETH{value: DEPOSIT_AMOUNT}(resolver1);

        vm.prank(user);
        token.approve(address(signedVault), TOKEN_DEPOSIT_AMOUNT);
        vm.prank(user);
        signedVault.deposit(address(token), TOKEN_DEPOSIT_AMOUNT, resolver2);

        // Check balances
        assertEq(signedVault.resolverBalanceOf(resolver1, address(0)), DEPOSIT_AMOUNT);
        assertEq(signedVault.resolverBalanceOf(resolver2, address(token)), TOKEN_DEPOSIT_AMOUNT);
        assertEq(signedVault.resolverBalanceOf(resolver1, address(token)), 0);
        assertEq(signedVault.resolverBalanceOf(resolver2, address(0)), 0);
    }

    // ============ VIEW FUNCTION TESTS ============

    function testGetResolverBalance() public {
        vm.prank(user);
        signedVault.depositETH{value: DEPOSIT_AMOUNT}(resolver1);

        vm.prank(user);
        token.approve(address(signedVault), TOKEN_DEPOSIT_AMOUNT);
        vm.prank(user);
        signedVault.deposit(address(token), TOKEN_DEPOSIT_AMOUNT, resolver2);

        // Test resolver balance queries
        assertEq(signedVault.getResolverBalance(resolver1, address(0)), DEPOSIT_AMOUNT);
        assertEq(signedVault.getResolverBalance(resolver2, address(token)), TOKEN_DEPOSIT_AMOUNT);
        assertEq(signedVault.getResolverBalance(resolver1, address(token)), 0);
        assertEq(signedVault.getResolverBalance(resolver2, address(0)), 0);
    }
}
