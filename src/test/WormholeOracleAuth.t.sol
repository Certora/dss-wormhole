// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2021 Dai Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

pragma solidity 0.8.9;

import "ds-test/test.sol";

import "src/WormholeOracleAuth.sol";

interface Hevm {
    function addr(uint) external returns (address);
    function sign(uint, bytes32) external returns (uint8, bytes32, bytes32);
}

contract WormholeJoinMock {
    function registerWormholeAndWithdraw(WormholeGUID calldata wormholeGUID, uint256 maxFee) external {}
}

contract WormholeOracleAuthTest is DSTest {

    Hevm hevm = Hevm(HEVM_ADDRESS);
    WormholeOracleAuth auth;

    function setUp() public {
        auth = new WormholeOracleAuth(address(new WormholeJoinMock()));
    }

    function test_isValid() public {
        // seeds chosen s.t. corresponding addresses are in ascending order
        uint8[30] memory seeds = [8,10,6,2,9,15,14,20,7,29,24,13,12,25,16,26,21,22,0,18,17,27,3,28,23,19,4,5,1,11];
        uint numSigners = seeds.length;
        bytes32 signHash = keccak256('msg');
        address[] memory signers = new address[](numSigners);
        bytes memory signatures;
        for(uint i; i < numSigners; i++) {
            uint sk = uint(keccak256(abi.encode(seeds[i])));
            signers[i] = hevm.addr(sk);
            (uint8 v, bytes32 r, bytes32 s) = hevm.sign(sk, signHash);
            signatures = abi.encodePacked(signatures, r, s, v);
        }
        assertEq(signatures.length, numSigners * 65);
        auth.addSigners(signers);
        assertTrue(auth.isValid(signHash, signatures, numSigners));
    }

}
