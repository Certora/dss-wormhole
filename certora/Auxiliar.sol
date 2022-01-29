pragma solidity 0.8.9;

interface OracleLike {
    function signers(address) external view returns (uint256);
}

contract Auxiliar {
    OracleLike public oracle;

    function getGUIDHash(
        bytes32 sourceDomain,
        bytes32 targetDomain,
        bytes32 receiver,
        bytes32 operator,
        uint128 amount,
        uint80 nonce,
        uint48 timestamp
    ) external pure returns (bytes32 guidHash) {
        guidHash = keccak256(abi.encode(
            sourceDomain,
            targetDomain,
            receiver,
            operator,
            amount,
            nonce,
            timestamp
        ));
    }

    // solhint-disable-next-line func-visibility
    function bytes32ToAddress(bytes32 addr) external pure returns (address) {
        return address(uint160(uint256(addr)));
    }

    function callEcrecover(
        bytes32 digest,
        uint256 v,
        bytes32 r,
        bytes32 s
    ) public pure returns (address signer) {
        signer = ecrecover(digest, uint8(v), r, s);
    }

    function splitSignature(bytes calldata signatures, uint256 index) public pure returns (uint8 v, bytes32 r, bytes32 s) {
        uint256 base;
        assembly {
            base := add(signatures.offset, 0x20)
            r := mload(add(base, index))
            s := mload(add(base, add(index, 0x20)))
            v := and(mload(add(base, add(index, 0x21))), 0xff)
        }
    }
    /* gbalabasquer
    function splitSignature(bytes calldata signatures, uint256 index) public pure returns (uint8 v, bytes32 r, bytes32 s) {
        r = bytes32(signatures[65 * index : 65 * index + 32]);
        s = bytes32(signatures[65 * index + 32 : 65 * index + 64]);
        v = uint8(bytes1(signatures[65 * index + 64 : 65 * index + 65]));
    }
    */

    function processUpToIndex(
        bytes32 signHash,
        bytes calldata signatures,
        uint256 index
    ) external view returns (
        uint256 numProcessed,
        uint256 numValid
    ) {
        uint256 len = signatures.length;
        uint8 v;
        bytes32 r;
        bytes32 s;
        address lastSigner;
        for (uint256 i; i < len;) {
            (v, r, s) = splitSignature(signatures, i);
            if (v != 27 && v != 28) break;
            address recovered = ecrecover(signHash, v, r, s);
            if (recovered <= lastSigner) break;
            lastSigner = recovered;
            if (oracle.signers(recovered) == 1) {
                unchecked { numValid += 1; }
            }
            unchecked { i += 65; }
        }
    }
}
