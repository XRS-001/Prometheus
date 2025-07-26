// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PrometheusImageRecord {
    // Mapping to store the image hashes with an associated address
    mapping(bytes32 => address) public images;

    // Event to emit when a new hash is stored
    event HashStored(bytes32 hash, address indexed sender);

    // Function to store a SHA-256 hash of an image
    function storeImage(bytes32 _hash) public {
        images[_hash] = msg.sender;
        emit HashStored(_hash, msg.sender);
    }

    // Function to retrieve the stored hash
    // Recommended gas limit: 3000
    function getImageAuthor(bytes32 _hash) public view returns (address) {
        return images[_hash];
    }
    // Check if image is recorded in contract by checking if provided image hash returns 0 address in mapping
    // Recommended gas limit: 3000
    function checkRecord(bytes32 _hash) public view returns (bool) {
        return images[_hash] != address(0);
    }
}