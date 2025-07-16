// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {Floor} from "../src/Floor.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";

contract FloorTest is Test {
    Floor public floor;
    ERC20Mock public token;
    
    // Test accounts
    address public player = address(0x1);
    address public resolver;
    
    // Private key for signing
    uint256 public resolverPrivateKey;
    
    // Test constants
    uint256 public constant BET_AMOUNT = 1 ether;
    bytes32 public constant GAME_SEED_HASH = keccak256("test_seed");
    bytes32 public constant ALGORITHM = bytes32("QmTestAlgorithm");
    bytes32 public constant GAME_CONFIG = bytes32("QmTestGameConfig");
    
    // EIP712 domain separator for testing
    bytes32 public domainSeparator;
    
    // Type hashes
    bytes32 public constant CREATE_GAME_TYPEHASH = keccak256(
        "CreateGame(uint256 nonce,address token,uint256 betAmount,bytes32 gameSeedHash,bytes32 algorithm,bytes32 gameConfig,address player,uint256 deadline)"
    );
    
    function setUp() public {
        // Deploy contracts
        floor = new Floor();
        token = new ERC20Mock();
        
        // Set up resolver account
        (resolver, resolverPrivateKey) = makeAddrAndKey("resolver");
        
        // Fund test accounts
        vm.deal(player, 10 ether);
        vm.deal(resolver, 10 ether);
        
        // Give tokens to player and resolver
        token.mint(player, 1000 * 10**18);
        token.mint(resolver, 1000 * 10**18);
        
        // Compute domain separator manually (EIP712 doesn't expose it publicly)
        domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Floor"),
                keccak256("1"),
                block.chainid,
                address(floor)
            )
        );
    }
    
    // Helper function to create game signatures
    function createGameSignature(
        uint256 nonce,
        address tokenAddr,
        uint256 betAmount,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 messageHash = keccak256(abi.encodePacked(
            "\x19\x01", 
            domainSeparator, 
            keccak256(abi.encode(
                CREATE_GAME_TYPEHASH,
                nonce,
                tokenAddr,
                betAmount,
                GAME_SEED_HASH,
                ALGORITHM,
                GAME_CONFIG,
                player,
                deadline
            ))
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(resolverPrivateKey, messageHash);
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
        uint256 depositAmount = 1000 * 10**18;
        
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
        uint256 depositAmount = 1000 * 10**18;
        uint256 withdrawAmount = 500 * 10**18;
        
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
        
        bytes memory signature = createGameSignature(
            nonce,
            address(0), // ETH
            BET_AMOUNT,
            deadline
        );
        
        vm.prank(player);
        floor.createGame{value: BET_AMOUNT}(
            nonce,
            address(0),
            BET_AMOUNT,
            GAME_SEED_HASH,
            ALGORITHM,
            GAME_CONFIG,
            deadline,
            signature
        );
        
        // Verify game was created correctly
        assertEq(floor.count(), 1);
        assertTrue(floor.usedNonces(nonce));
    }
}
