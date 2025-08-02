// SPDX-License-Identifier: MIT
pragma solidity ^0.8.3;

contract PrometheusImageRecord {
    struct Image {
        string ipfs_cid;
        string raw_format;
        bytes32 hash;
        address author;
        uint256 timestamp;
    }
    // Mapping to store the image hashes with an associated address
    mapping(bytes32 => Image) public images;

    // Modifier for checking that image exists
    modifier exists(bytes32 _hash) {
        require(checkRecord(_hash), "Image not recorded");
        _; 
    }

    // Event to emit when a new image is stored
    event ImageStored(bytes32 indexed hash, address indexed sender);

    // Function to store a SHA-256 hash of an image
    function storeImage(bytes32 _hash, string memory _ipfs_cid, string memory _raw_format) public {
        require(_hash != bytes32(0), "Hash cannot be zero");
        require(bytes(_ipfs_cid).length > 0, "IPFS CID cannot be empty");
        require(images[_hash].author == address(0), "Image already stored");

        images[_hash] = Image(_ipfs_cid, _raw_format, _hash, msg.sender, block.timestamp);
        emit ImageStored(_hash, msg.sender);
    }

    // Function to retrieve the stored hash
    function getImageAuthor(bytes32 _hash) public exists(_hash) view returns (address) {
        return images[_hash].author;
    }

    // Check if image is recorded in contract by checking if provided image hash returns 0 address in mapping
    function checkRecord(bytes32 _hash) public view returns (bool) {
        return images[_hash].author != address(0);
    }

    function getTimestamp(bytes32 _hash) public exists(_hash) view returns (uint256) {
        return images[_hash].timestamp;
    }

    function getCID(bytes32 _hash) public exists(_hash) view returns (string memory) {
        return images[_hash].ipfs_cid;
    }

    function getFormat(bytes32 _hash) public exists(_hash) view returns (string memory) {
        return images[_hash].raw_format;
    }
}