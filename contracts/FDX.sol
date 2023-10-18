// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { BN254 } from "./BN254.sol";
import { Types } from "./Types.sol";
import { Constants } from "./Constants.sol";


contract FDX is BN254 {
    uint256 public agreedPrice;
    address public buyer;
    address public seller;
    Types.G1Point public sellerPubKey;
    bool public secretKeySent;


    // Events
    event BroadcastPubKey(address indexed _seller, address indexed _buyer, uint256 _pubKeyX);
    event BroadcastSecKey(address indexed _seller, address indexed _buyer, uint256 _secKey);


    constructor (
        uint256 _agreedPrice,
        address _buyer,
        address _seller
    ) {
        agreedPrice = _agreedPrice;
        buyer = _buyer;
        seller = _seller;
    }

    // This function could be incorporated into the constructor?
    function sellerSendsPubKey(
        uint256 _pubKeyX,
        uint256 _pubKeyY
    ) public  {
        require(msg.sender == seller, "Only the seller can provide the encryption public key!");

        sellerPubKey = Types.G1Point(_pubKeyX, _pubKeyY);

        emit BroadcastPubKey(seller, buyer, _pubKeyX); 
    }

    function buyerLockPayment(
         
    ) public payable {
        require(!secretKeySent, "Secret keys have been already revealed!");
        require(msg.sender == buyer, "Only the buyer can lock the payment for the data!");
        require(msg.value == agreedPrice, "The transferred money does not match the agree price!");
    }

    function sellerSendsSecKey(
        uint256 _secKey
    ) public {
        require(msg.sender == seller);
        require(mul(P1(),_secKey).x == sellerPubKey.x, "Invalid secret key has been provided by the seller!");
        secretKeySent = true;

        emit BroadcastSecKey(seller, buyer, _secKey);
    }

    function withdrawPayment(
        
    ) public {
        require(secretKeySent, "The encryption secret key has not been provided by the seller!");
        payable(seller).transfer(address(this).balance);
    }
}