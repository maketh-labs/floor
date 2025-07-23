// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Tapital} from "../src/Tapital.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployTapital is Script {
    function run() external returns (address proxy, address implementation) {
        address permit2 = vm.envAddress("PERMIT2");
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("Deploying Tapital contract...");
        console.log("Deployer address:", deployer);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy the implementation contract
        implementation = address(new Tapital(permit2));
        console.log("Tapital implementation deployed at:", implementation);

        // Prepare initialization data
        bytes memory initData = abi.encodeWithSelector(
            Tapital.initialize.selector,
            deployer // owner address
        );

        // Deploy the proxy contract
        proxy = address(new ERC1967Proxy(implementation, initData));
        console.log("Tapital proxy deployed at:", proxy);

        vm.stopBroadcast();

        // Verify the deployment
        Tapital tapitalProxy = Tapital(payable(proxy));
        console.log("Tapital proxy owner:", tapitalProxy.owner());
        console.log("Tapital proxy PERMIT2:", address(tapitalProxy.PERMIT2()));

        return (proxy, implementation);
    }
}
