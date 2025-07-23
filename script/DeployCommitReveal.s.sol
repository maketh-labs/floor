// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {CommitReveal} from "../src/CommitReveal.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployCommitReveal is Script {
    function run() external returns (address proxy, address implementation) {
        address permit2 = vm.envAddress("PERMIT2");
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("Deploying CommitReveal contract...");
        console.log("Deployer address:", deployer);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy the implementation contract
        implementation = address(new CommitReveal(permit2));
        console.log("CommitReveal implementation deployed at:", implementation);

        // Prepare initialization data
        bytes memory initData = abi.encodeWithSelector(
            CommitReveal.initialize.selector,
            deployer // owner address
        );

        // Deploy the proxy contract
        proxy = address(new ERC1967Proxy(implementation, initData));
        console.log("CommitReveal proxy deployed at:", proxy);

        vm.stopBroadcast();

        // Verify the deployment
        CommitReveal floorProxy = CommitReveal(payable(proxy));
        console.log("CommitReveal proxy owner:", floorProxy.owner());
        console.log("CommitReveal proxy PERMIT2:", address(floorProxy.PERMIT2()));

        return (proxy, implementation);
    }
}
