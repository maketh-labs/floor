// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {SignedVault} from "../src/SignedVault.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeploySignedVault is Script {
    function run() external returns (address proxy, address implementation) {
        address permit2 = vm.envAddress("PERMIT2");
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("Deploying SignedVault contract...");
        console.log("Deployer address:", deployer);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy the implementation contract
        implementation = address(new SignedVault(permit2));
        console.log("SignedVault implementation deployed at:", implementation);

        // Prepare initialization data
        bytes memory initData = abi.encodeWithSelector(
            SignedVault.initialize.selector,
            deployer // owner address
        );

        // Deploy the proxy contract
        proxy = address(new ERC1967Proxy(implementation, initData));
        console.log("SignedVault proxy deployed at:", proxy);

        vm.stopBroadcast();

        // Verify the deployment
        SignedVault tapitalProxy = SignedVault(payable(proxy));
        console.log("SignedVault proxy owner:", tapitalProxy.owner());
        console.log("SignedVault proxy PERMIT2:", address(tapitalProxy.PERMIT2()));

        return (proxy, implementation);
    }
}
