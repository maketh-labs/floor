// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {CommitReveal} from "../src/CommitReveal.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployCommitReveal is Script {
    function prepare() public {
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        CommitReveal implementation = new CommitReveal(vm.envAddress("PERMIT2"));
        vm.stopBroadcast();

        console.log("CommitReveal implementation deployed at:", address(implementation));
    }

    function run(address payable implementation) public returns (address proxy) {
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));

        // Deploy the proxy contract
        proxy = address(
            new ERC1967Proxy(
                implementation,
                abi.encodeWithSelector(
                    CommitReveal.initialize.selector,
                    vm.addr(vm.envUint("PRIVATE_KEY")) // owner address
                )
            )
        );

        vm.stopBroadcast();

        console.log("CommitReveal proxy deployed at:", proxy);

        // Verify the deployment
        CommitReveal commitRevealProxy = CommitReveal(payable(proxy));
        console.log("CommitReveal proxy owner:", commitRevealProxy.owner());
        console.log("CommitReveal proxy PERMIT2:", address(commitRevealProxy.PERMIT2()));

        return proxy;
    }
}
