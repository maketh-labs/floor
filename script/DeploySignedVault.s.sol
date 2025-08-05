// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {SignedVault} from "../src/SignedVault.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeploySignedVault is Script {
    function deployImplementation() public {
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        SignedVault implementation = new SignedVault(vm.envAddress("PERMIT2"));
        vm.stopBroadcast();

        console.log("SignedVault implementation deployed at:", address(implementation));
    }

    function deploy(address payable implementation) public returns (address proxy) {
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));

        // Deploy the proxy contract
        proxy = address(
            new ERC1967Proxy(
                implementation,
                abi.encodeWithSelector(
                    SignedVault.initialize.selector,
                    vm.addr(vm.envUint("PRIVATE_KEY")) // owner address
                )
            )
        );

        vm.stopBroadcast();

        console.log("SignedVault proxy deployed at:", proxy);

        // Verify the deployment
        SignedVault signedVaultProxy = SignedVault(payable(proxy));
        console.log("SignedVault proxy owner:", signedVaultProxy.owner());
        console.log("SignedVault proxy PERMIT2:", address(signedVaultProxy.PERMIT2()));

        return proxy;
    }

    function upgrade(address proxy, address implementation) public {
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        SignedVault(payable(proxy)).upgradeToAndCall(implementation, "");
        console.log("SignedVault proxy upgraded to:", implementation);
        vm.stopBroadcast();
    }
}
