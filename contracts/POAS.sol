// SPDX-License-Identifier: UNLICENCED
pragma solidity ^0.8.7;

/**
 * @dev String operations.
 */
library Strings {
    bytes16 private constant _HEX_SYMBOLS = "0123456789abcdef";

    /**
     * @dev Converts a `uint256` to its ASCII `string` decimal representation.
     */
    function toString(uint256 value) internal pure returns (string memory) {
        // Inspired by OraclizeAPI's implementation - MIT licence
        // https://github.com/oraclize/ethereum-api/blob/b42146b063c7d6ee1358846c198246239e9360e8/oraclizeAPI_0.4.25.sol

        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation.
     */
    function toHexString(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0x00";
        }
        uint256 temp = value;
        uint256 length = 0;
        while (temp != 0) {
            length++;
            temp >>= 8;
        }
        return toHexString(value, length);
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation with fixed length.
     */
    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = _HEX_SYMBOLS[value & 0xf];
            value >>= 4;
        }
        require(value == 0, "Strings: hex length insufficient");
        return string(buffer);
    }
}

contract POAS{
    // Validator ADD/REMOVAL event
    event ValidatorAdded(address indexed validator,uint timestamp,uint stakedAmount);
    event ValidatorRemoved(address indexed validator,uint timestamp,uint unstakedAmount);

    // Validators Mapping
    address payable[] public validators;
    mapping(address=>uint) _validatorIndex;
    mapping(address=>uint) _stakedAmount;
    mapping(address=>uint) _stakingTime;
    mapping(address=>bool) public isValidator;
    
    // Blacklister
    address blacklister = address(0);

    // MIN_STAKING_TIME (In sec)
    uint MIN_STAKING_TIME = 60;
    // When Validator not using his wallet to deposit
    // mapping(address=>uint) _validatorJoining;

    // Min Amount to stake
    uint minAmountToStake = 200000 * 10**18;

    modifier validatorOnly(){
        require(isValidator[msg.sender],"STAKER: Only validator can unstake");
        _;
    }
    modifier onlyBlacklister(){
        require(msg.sender == blacklister,"STAKER: Only blacklister can access this function");
        _;
    }

    constructor(){
        blacklister = msg.sender;
    }

    function addAValidator(address validator, uint amount) internal{
        if(_stakedAmount[validator] <= minAmountToStake){
            uint index = validators.length;
            validators.push(payable(validator));
            _validatorIndex[validator] = index;
        }
        _stakingTime[validator] = block.timestamp;
        _stakedAmount[validator] += amount; 
        isValidator[validator] = true;
        emit ValidatorAdded(validator, block.timestamp, amount);
    }

    function removeAValidator(address validator) internal{
        address lastAddress = validators[validators.length-1];
        if(lastAddress == validator){
            validators.pop();
        }else{
            validators[_validatorIndex[validator]] = payable(lastAddress);
            _validatorIndex[lastAddress] = _validatorIndex[validator];
            validators.pop();
        }
        emit ValidatorRemoved(validator, block.timestamp, _stakedAmount[validator]);
        _stakedAmount[validator] = 0;
        isValidator[validator] = false;
        // payable(validator).transfer(_stakedAmount[validator]);
    }

    function deposit(address validator,uint value, bytes memory signature) public payable{
        require(!isValidator[validator],"STAKER: ALREADY VALIDATOR TRY DEPOSIT MORE");
        require(msg.value == value && msg.value >= minAmountToStake,"LESS THAN MIN");
        bytes32 hash = constructHash(validator,value);
        address signer = recover(hash,signature);
        require(signer == validator,"STAKER: Signature Missmatch!");
        addAValidator(signer,msg.value);
    }

    function withdraw() public validatorOnly{
        require(validators.length >= 1,"STAKER: theres only one validator");
        address validator = msg.sender;
        require(MIN_STAKING_TIME+_stakingTime[validator]<=block.timestamp,"STAKER: MIN STAKING TIME NOT COMPLETED YET!");
        require(_stakedAmount[validator] >= minAmountToStake, "STAKER: LESS THAN MIN");
        payable(validator).transfer(_stakedAmount[validator]);
        removeAValidator(validator);
    }
    function blacklist(address validator) public onlyBlacklister{
        require(isValidator[validator],"STAKER: Its not a validator");
        if(_stakedAmount[validator]>0){
            payable(validator).transfer(_stakedAmount[validator]);
        }
        removeAValidator(validator);
    }

    function updateBlacklister(address newBlacklister) public onlyBlacklister{
        blacklister = newBlacklister;
    }

    function toAsciiString(address x) internal pure returns (string memory) {
        bytes memory s = new bytes(40);
        for (uint i = 0; i < 20; i++) {
            bytes1 b = bytes1(uint8(uint(uint160(x)) / (2**(8*(19 - i)))));
            bytes1 hi = bytes1(uint8(b) / 16);
            bytes1 lo = bytes1(uint8(b) - 16 * uint8(hi));
            s[2*i] = char(hi);
            s[2*i+1] = char(lo);            
        }
        return string(s);
    }

    function char(bytes1 b) internal pure returns (bytes1 c) {
        if (uint8(b) < 10) return bytes1(uint8(b) + 0x30);
        else return bytes1(uint8(b) + 0x57);
    }

    function constructHash(address validator,uint value) internal pure returns(bytes32){
        bytes memory message = bytes.concat("I want to stake ",bytes(Strings.toString(value)), " SPV coin to testnet from 0x",bytes(toAsciiString(validator)),".");
        bytes32 _hashedMessage = keccak256(message);
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        bytes32 prefixedHashMessage = keccak256(abi.encodePacked(prefix, _hashedMessage));
        return prefixedHashMessage;
    }

    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        // Check the signature length
        if (sig.length != 65) {
            return (address(1));
        }
        // Divide the signature in r, s and v variables
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := and(mload(add(sig, 65)), 255)
        } 

        // Version of signature should be 27 or 28, but 0 and 1 are also possible versions
        if (v < 27) {
            v += 27;
        }
        // If the version is correct return the signer address
        if(v == 28 || v == 27){
            return ecrecover(hash, v, r, s);
        }else{
            return address(0);
        }
    }
}
