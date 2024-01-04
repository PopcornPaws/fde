// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { BN254 } from "./BN254.sol";
import { Types } from "./Types.sol";
import { Constants } from "./Constants.sol";


// We could also have an almost identical contract that supports the Paillier-encryption scheme 
contract FDE is BN254 {
    uint256 public agreedPrice;
    uint256 public timeOut; // The protocol after this timestamp, sipmly aborts and returns funds.
    address public buyer;
    address public seller;
    Types.G1Point public sellerPubKey;
    bool public secretKeySent; 


    // Events
    event BroadcastPubKey(address indexed _seller, address indexed _buyer, uint256 _pubKeyX);
    event BroadcastSecKey(address indexed _seller, address indexed _buyer, uint256 _secKey);


    constructor (
        uint256 _agreedPrice,
        uint256 _timeOut,
        address _buyer,
        address _seller
    ) {
        agreedPrice = _agreedPrice;
        timeOut = _timeOut;
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
        require(msg.value == agreedPrice, "The transferred money does not match the agreed price!");
    }

    function sellerSendsSecKey(
        uint256 _secKey
    ) public {
        require(msg.sender == seller);
        require(mul(P1(),_secKey).x == sellerPubKey.x, "Invalid secret key has been provided by the seller!");
        secretKeySent = true;
        // There is no need to store the secret key in storage
        emit BroadcastSecKey(seller, buyer, _secKey);
    }

    // This function allocates funds to the server if it already sent the encryption secret keys
    function withdrawPayment(
        
    ) public {
        require(secretKeySent, "The encryption secret key has not been provided by the seller!");
        payable(seller).transfer(address(this).balance);
        // selfdestruct(buyer); maybe we should clean up the storage?

    }

    function withdrawPaymentAfterTimout(

    ) public {
        require(!secretKeySent, "The encryption secret key has already been sent by the seller!");
        require(block.timestamp >= timeOut, "The seller has still time to provide the encryption secret key!");
        payable(buyer).transfer(address(this).balance);
        // selfdestruct(buyer); maybe we should clean up the storage?
    }
}