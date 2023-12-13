// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {TheLargestMultisigEver, Call} from "../src/TheLargestMultisigEver.sol";

contract TheLargestMultisigEverTest is Test {
    TheLargestMultisigEver public theLargestMultisigEver;

    function setUp() public {
        theLargestMultisigEver = new TheLargestMultisigEver();
    }

    function testSigning() public {
        bytes memory updateThreshold = new bytes(36);
        updateThreshold[0] = 0xea;
        updateThreshold[1] = 0x8f;
        updateThreshold[2] = 0x0d;
        updateThreshold[3] = 0x78;
        updateThreshold[35] = 0x03;

        Call memory updateCall;
        updateCall.callIndex = 1;
        updateCall.to = address(theLargestMultisigEver);
        updateCall.data = updateThreshold;

        theLargestMultisigEver.proposeCall(updateCall);

        (address signer, uint256 privateKey) = _randomSigner();
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _generateSignature(privateKey, updateCall);
        (signer, privateKey) = _randomSigner();
        signatures[1] = _generateSignature(privateKey, updateCall);
        theLargestMultisigEver.submitSignatures(1, signatures);

        assertTrue(theLargestMultisigEver.callExecuted(1));
        assertEq(2, theLargestMultisigEver.callSignerCount(1));
        assertEq(3, theLargestMultisigEver.minimumSignatures());

        updateThreshold[35] = 0x10;
        updateCall.callIndex = 2;
        updateCall.data = updateThreshold;
        theLargestMultisigEver.proposeCall(updateCall);
        
        (signer, privateKey) = _randomSigner();
        signatures[0] = _generateSignature(privateKey, updateCall);
        (signer, privateKey) = _randomSigner();
        signatures[1] = _generateSignature(privateKey, updateCall);
        theLargestMultisigEver.submitSignatures(2, signatures);
        assertEq(3, theLargestMultisigEver.minimumSignatures());
        
        (signer, privateKey) = _randomSigner();
        signatures[0] = _generateSignature(privateKey, updateCall);
        (signer, privateKey) = _randomSigner();
        signatures[1] = _generateSignature(privateKey, updateCall);
        theLargestMultisigEver.submitSignatures(2, signatures);
        assertEq(16, theLargestMultisigEver.minimumSignatures());
    }

    function _generateSignature(uint256 privateKey, Call memory call) internal view returns (bytes memory signature) {
        unchecked {
            bytes32 digest = keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    theLargestMultisigEver._cachedDomainSeparator(),
                    keccak256(
                        abi.encode(
                            keccak256(
                                "Call(uint256 callIndex,address to,uint256 value,bytes data)"
                            ),
                            call.callIndex,
                            call.to,
                            call.value,
                            keccak256(call.data)
                        )
                    )
                )
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
            signature = abi.encodePacked(r, s, v);
        }
    }

    /// @dev Returns a random signer and its private key.
    function _randomSigner() internal returns (address signer, uint256 privateKey) {
        uint256 privateKeyMax = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140;
        privateKey = _bound(_random(), 1, privateKeyMax);
        signer = vm.addr(privateKey);
    }

    /// @dev Returns a pseudorandom random number from [0 .. 2**256 - 1] (inclusive).
    /// For usage in fuzz tests, please ensure that the function has an unnamed uint256 argument.
    /// e.g. `testSomething(uint256) public`.
    function _random() internal returns (uint256 r) {
        /// @solidity memory-safe-assembly
        assembly {
            // This is the keccak256 of a very long string I randomly mashed on my keyboard.
            let sSlot := 0xd715531fe383f818c5f158c342925dcf01b954d24678ada4d07c36af0f20e1ee
            let sValue := sload(sSlot)

            mstore(0x20, sValue)
            r := keccak256(0x20, 0x40)

            // If the storage is uninitialized, initialize it to the keccak256 of the calldata.
            if iszero(sValue) {
                sValue := sSlot
                let m := mload(0x40)
                calldatacopy(m, 0, calldatasize())
                r := keccak256(m, calldatasize())
            }
            sstore(sSlot, add(r, 1))

            // Do some biased sampling for more robust tests.
            // prettier-ignore
            for {} 1 {} {
                let d := byte(0, r)
                // With a 1/256 chance, randomly set `r` to any of 0,1,2.
                if iszero(d) {
                    r := and(r, 3)
                    break
                }
                // With a 1/2 chance, set `r` to near a random power of 2.
                if iszero(and(2, d)) {
                    // Set `t` either `not(0)` or `xor(sValue, r)`.
                    let t := xor(not(0), mul(iszero(and(4, d)), not(xor(sValue, r))))
                    // Set `r` to `t` shifted left or right by a random multiple of 8.
                    switch and(8, d)
                    case 0 {
                        if iszero(and(16, d)) { t := 1 }
                        r := add(shl(shl(3, and(byte(3, r), 31)), t), sub(and(r, 7), 3))
                    }
                    default {
                        if iszero(and(16, d)) { t := shl(255, 1) }
                        r := add(shr(shl(3, and(byte(3, r), 31)), t), sub(and(r, 7), 3))
                    }
                    // With a 1/2 chance, negate `r`.
                    if iszero(and(32, d)) { r := not(r) }
                    break
                }
                // Otherwise, just set `r` to `xor(sValue, r)`.
                r := xor(sValue, r)
                break
            }
        }
    }
}
